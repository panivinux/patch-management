#!/usr/bin/env bash
# =============================================================================
#  PATCH MANAGEMENT EMPRESARIAL - UBUNTU SERVER 26.04 LTS
#  Actualización controlada, validación y documentación (Fases 1-12)
#
#  Uso (como root):
#    sudo ./patch-management-ubuntu.sh --skip-install     # prueba segura: sin instalar
#    sudo ./patch-management-ubuntu.sh --auto-reboot      # corrida completa con reinicio automático
#    sudo ./patch-management-ubuntu.sh --continue         # continuar tras un reinicio manual
#
#  Opciones:
#    --expected-ip IP     (opcional) verifica que esté en el servidor correcto; por defecto detecta la IP sola
#    --responsable NOMBRE (por defecto "Marcelo Gallardo")
#    --min-free-gb N      espacio libre mínimo en / (por defecto 10)
#    --event-days N       ventana de análisis de logs (por defecto 7)
#    --skip-install       no instala (solo inventario, pre-check, respaldos, escaneo, validaciones)
#    --auto-reboot        si hay reinicio pendiente: reinicia y continúa solo (servicio systemd)
#    --apply-hardening    aplica un drop-in sysctl reversible (nada más)
#    --allow-removals     permite instalar aunque full-upgrade vaya a ELIMINAR paquetes
#    --include-snap       ejecuta también 'snap refresh'
#    --force              no aborta si la IP no coincide
#    --continue           continúa la corrida pendiente de reinicio
#
#  Nunca inventa resultados: todo proviene de comandos ejecutados en el servidor.
#
#  Autor: Marcelo Gallardo - Autor • Investigador • Ingeniero en Sistemas
#  https://panivinux.base44.app/
# =============================================================================
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l
set -o pipefail

EXPECTED_IP=""; RESPONSABLE="Marcelo Gallardo"; MIN_FREE_GB=10; EVENT_DAYS=7
BASE="/opt/PatchManagement"; BACKUP="/var/backups/PatchBackup"
SKIP_INSTALL=0; AUTO_REBOOT=0; APPLY_HARD=0; ALLOW_REMOVE=0; INCLUDE_SNAP=0; FORCE=0; CONTINUE=0
ORIG_ARGS=("$@")
while [ $# -gt 0 ]; do
  case "$1" in
    --expected-ip) EXPECTED_IP="$2"; shift;;
    --responsable) RESPONSABLE="$2"; shift;;
    --min-free-gb) MIN_FREE_GB="$2"; shift;;
    --event-days) EVENT_DAYS="$2"; shift;;
    --skip-install) SKIP_INSTALL=1;;
    --auto-reboot) AUTO_REBOOT=1;;
    --apply-hardening) APPLY_HARD=1;;
    --allow-removals) ALLOW_REMOVE=1;;
    --include-snap) INCLUDE_SNAP=1;;
    --force) FORCE=1;;
    --continue) CONTINUE=1;;
    -h|--help) sed -n '2,26p' "$0"; exit 0;;
    *) echo "Opción desconocida: $1"; exit 2;;
  esac; shift
done

[ "$(id -u)" -eq 0 ] || { echo "Ejecute como root (sudo)."; exit 1; }
SCRIPT_PATH="$(readlink -f "$0")"
# IP principal detectada automáticamente (el script funciona en cualquier servidor)
SERVER_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
[ -n "$SERVER_IP" ] || SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$SERVER_IP" ] || SERVER_IP="n/d"
HC_SCRIPT="/usr/local/sbin/patchmgmt-healthcheck.sh"
mkdir -p "$BASE" "$BACKUP"; chmod 700 "$BACKUP"
exec 9>/run/patchmgmt.lock
flock -n 9 || { echo "Ya hay otra instancia en ejecución."; exit 1; }

if [ "$CONTINUE" -eq 1 ]; then
  [ -f "$BASE/current_run" ] || { echo "No hay corrida previa (current_run)."; exit 1; }
  RUN_ID="$(cat "$BASE/current_run")"
else
  RUN_ID="$(date +%Y%m%d_%H%M%S)"; echo "$RUN_ID" > "$BASE/current_run"
fi
RUN="$BASE/Run_$RUN_ID"; EV="$BASE/Evidencias/$RUN_ID"; META="$RUN/meta"; SEC="$RUN/sec"
FIND="$RUN/findings.tsv"; EVI="$RUN/evid.tsv"
mkdir -p "$RUN" "$EV" "$META" "$SEC"; touch "$FIND" "$EVI"
if [ "$CONTINUE" -eq 0 ]; then date +%s > "$META/start_epoch"; date '+%F %T' > "$META/start"; fi
exec > >(tee -a "$RUN/transcript.log") 2>&1

CUR=""; EVF=""; EVRC=0; BT='`'; NL=$'\n'

# ------------------------------------------------------------------ helpers
ico() { case "$1" in OK) printf '🟢';; WARN) printf '🟡';; RISK) printf '🔴';; *) printf 'ℹ️';; esac; }
hdr() { echo; printf '\033[36m=== %s ===\033[0m\n' "$1"; }
finding() {  # fase estado item detalle
  local d c; d="$(printf '%s' "$4" | tr '\t\n' '  ')"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$d" >> "$FIND"
  case "$2" in OK) c=32;; WARN) c=33;; RISK) c=31;; *) c=36;; esac
  printf '  \033[%sm[%s]\033[0m %s - %s\n' "$c" "$2" "$3" "$d"
}
sec()  { printf '%s' "$3" > "$SEC/$1.$2"; }          # fase clave texto
mset() { printf '%s' "$2" > "$META/$1"; }
mget() { [ -f "$META/$1" ] && cat "$META/$1"; }
fmt_dur() { printf '%02d:%02d:%02d' $(($1/3600)) $(($1%3600/60)) $(($1%60)); }
ev() {       # nombre "comando"  -> guarda salida como evidencia; EVF=archivo, EVRC=exit
  local name="$1" cmd="$2" f="$EV/${CUR}_$1.txt" out rc
  out="$(bash -c "$cmd" 2>&1)"; rc=$?
  { echo "# Comando: $cmd"; echo "# Fecha: $(date -Is)"; printf '%s\n' "$out"; echo "# exit=$rc"; } > "$f"
  printf '%s\t%s\t%s\t%s\n' "$CUR" "$name" "$cmd" "$f" >> "$EVI"
  EVF="$f"; EVRC=$rc
}
evbody() { grep -v '^# ' "$EVF"; }
evfile() { printf '%s\t%s\t%s\t%s\n' "$CUR" "$1" "$3" "$2" >> "$EVI"; }   # nombre ruta comando
worst() { awk -F'\t' -v p=" $* " 'index(p, " " $1 " ")>0 { if($2=="RISK") r=1; else if($2=="WARN") w=1 } END{ print r?"RISK":(w?"WARN":"OK") }' "$FIND"; }
unit_exists() { systemctl list-unit-files "$1.service" --no-legend 2>/dev/null | grep -q "^$1.service"; }
free_gb() { df -P -BG "$1" 2>/dev/null | awk 'NR==2{gsub("G","",$4); print $4+0}'; }

reboot_reasons() {
  local r="" run newest
  [ -f /var/run/reboot-required ] && r="reboot-required"
  [ -f /var/run/reboot-required.pkgs ] && r="$r (paquetes: $(sort -u /var/run/reboot-required.pkgs | tr '\n' ' '))"
  run="$(uname -r)"
  newest="$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|/boot/vmlinuz-||' | sort -V | tail -1)"
  if [ -n "$newest" ] && [ "$newest" != "$run" ] && [ "$(printf '%s\n%s\n' "$run" "$newest" | sort -V | tail -1)" = "$newest" ]; then
    r="$r kernel en ejecución=$run, instalado=$newest"
  fi
  printf '%s' "$r"
}

ptitle() { case "$1" in
  F1) echo "Fase 1 - Inventario inicial";; F2) echo "Fase 2 - Pre-check de parcheo";; F3) echo "Fase 3 - Respaldos";;
  F4) echo "Fase 4 - Actualizaciones (APT)";; F5) echo "Fase 5 - Instalación controlada";; F6) echo "Fase 6 - Reinicio controlado";;
  F7) echo "Fase 7 - Validación posterior";; F8) echo "Fase 8 - Hardening posterior";; F9) echo "Fase 9 - Logs del sistema (journald)";;
  F10) echo "Fase 10 - Validación operativa";; F11) echo "Fase 11 - Health Check";; esac; }
kname() { case "$1" in EstadoInicial) echo "Estado inicial";; Evidencia) echo "Evidencia";; Diagnostico) echo "Diagnóstico";;
  Accion) echo "Acción ejecutada";; Resultado) echo "Resultado";; Validacion) echo "Validación";; Rollback) echo "Rollback";;
  Recomendaciones) echo "Recomendaciones";; Conclusion) echo "Conclusión";; esac; }

# ------------------------------------------------------------------ informes
phase_md() {  # fase [nivel]
  local ph="$1" lvl="${2:-##}" w k f
  w="$(worst "$ph")"
  echo "$lvl $(ptitle "$ph") $(ico "$w")"; echo
  for k in EstadoInicial Evidencia Diagnostico Accion Resultado Validacion Rollback Recomendaciones Conclusion; do
    echo "$lvl# $(kname $k)"; echo
    case "$k" in
      Evidencia)
        awk -F'\t' -v p="$ph" '$1==p{printf "- Comando: `%s` -> Evidencia: `%s`\n",$3,$4}' "$EVI" > "$RUN/.tmp"
        if [ -s "$RUN/.tmp" ]; then cat "$RUN/.tmp"; else echo "- Sin evidencias generadas en esta fase."; fi;;
      Diagnostico)
        awk -F'\t' -v p="$ph" '$1==p{print "- ["$2"] **"$3"**: "$4}' "$FIND" | sed 's/^- \[OK\]/- 🟢/; s/^- \[WARN\]/- 🟡/; s/^- \[RISK\]/- 🔴/; s/^- \[INFO\]/- ℹ️/' > "$RUN/.tmp"
        if [ -s "$RUN/.tmp" ]; then cat "$RUN/.tmp"; else echo "- Sin hallazgos registrados."; fi;;
      Conclusion)
        f="$SEC/$ph.Conclusion"; echo "Estado de la fase: $(ico "$w") $w. $([ -s "$f" ] && cat "$f")";;
      *)
        f="$SEC/$ph.$k"; if [ -s "$f" ]; then cat "$f"; echo; else echo "No registrado."; fi;;
    esac
    echo
  done
}
report_header() {  # titulo fases...
  local title="$1"; shift; local w; w="$(worst "$@")"
  cat <<EOF
# $title

- **Fecha:** $(date +%F)
- **Hora:** $(date +%T)
- **Servidor:** $(hostname) ($SERVER_IP) - $(. /etc/os-release; echo "$PRETTY_NAME")
- **Responsable:** $RESPONSABLE
- **Corrida:** $RUN_ID
- **Estado:** $(ico "$w") $w
- **Autor del script:** Marcelo Gallardo - Autor • Investigador • Ingeniero en Sistemas - https://panivinux.base44.app/

EOF
}
write_report() {  # archivo titulo fases...
  local file="$1" title="$2"; shift 2
  { report_header "$title" "$@"; local p; for p in "$@"; do phase_md "$p" '##'; echo; done; } > "$BASE/$file"
}

# =============================================================================
# FASE 1 - INVENTARIO INICIAL
# =============================================================================
fase1() {
  CUR=F1; hdr "FASE 1 - INVENTARIO INICIAL"
  ev hostname 'hostnamectl'
  ev os_release 'cat /etc/os-release; lsb_release -a 2>/dev/null'
  ev kernel 'uname -a'
  ev fecha_hora 'date -Is; timedatectl'
  ev uptime 'uptime -p; uptime -s; who -b'
  ev cpu 'lscpu'
  ev ram 'free -h; grep -E "MemTotal|SwapTotal" /proc/meminfo'
  ev discos_volumenes 'lsblk -f; echo; df -hT -x tmpfs -x devtmpfs -x squashfs'
  ev smart 'command -v smartctl >/dev/null || { echo "smartctl no instalado"; exit 0; }; lsblk -dno NAME,TYPE | while read -r n t; do [ "$t" = disk ] && { echo "== /dev/$n"; smartctl -H /dev/$n; }; done'
  local smart_txt; smart_txt="$(evbody)"
  ev interfaces 'ip -br addr; echo; ip addr'
  ev rutas_gateway 'ip route; echo; ip -6 route'
  ev dns 'resolvectl status 2>/dev/null || cat /etc/resolv.conf'
  ev puertos_abiertos 'ss -tulpn'
  ev servicios_running 'systemctl list-units --type=service --state=running --no-pager'
  ev servicios_enabled_disabled 'systemctl list-unit-files --type=service --no-pager'
  ev servicios_failed 'systemctl --failed --no-pager'
  ev paquetes_instalados 'dpkg-query -W -f="\${Package}\t\${Version}\n" | sort'
  ev snaps 'snap list 2>/dev/null || echo "snapd no presente"'
  ev contenedores 'docker ps -a 2>/dev/null || echo "docker no presente"'
  ev ufw_estado 'ufw status verbose 2>/dev/null || echo "ufw no presente"'

  dpkg-query -W -f='${Package}\t${Version}\n' | sort > "$META/pkgs_before"
  docker ps --format '{{.Names}}' 2>/dev/null | sort > "$META/ctr_before"
  systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | sort > "$META/failed_before"
  mset kernel_before "$(uname -r)"

  . /etc/os-release
  if [ "$ID" = "ubuntu" ] && [[ "$VERSION_ID" == 26.04* ]]; then finding F1 OK "Sistema operativo" "$PRETTY_NAME | kernel $(uname -r) | $(dpkg --print-architecture)"
  else finding F1 WARN "Sistema operativo" "$PRETTY_NAME (script diseñado para Ubuntu 26.04 LTS)"; fi
  local ips; ips="$(ip -4 -o addr 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
  [ -n "$ips" ] || ips="$(hostname -I 2>/dev/null)"
  if [ -n "$EXPECTED_IP" ]; then
    if printf '%s\n' "$ips" | grep -qx "$EXPECTED_IP"; then finding F1 OK "Dirección IP" "Coincide con la IP esperada $EXPECTED_IP"
    else
      finding F1 RISK "Dirección IP" "Este equipo NO tiene la IP esperada $EXPECTED_IP (IPs: $(echo $ips))"
      [ "$FORCE" -eq 1 ] || { echo "Abortando: IP no coincide. Use --force si está seguro."; exit 1; }
    fi
  else finding F1 INFO "Dirección IP" "IP principal detectada: $SERVER_IP (todas: $(echo $ips))"; fi
  local upd; upd=$(( $(cut -d. -f1 /proc/uptime) / 86400 ))
  if [ "$upd" -gt 45 ]; then finding F1 WARN "Uptime" "$upd días"; else finding F1 OK "Uptime" "$upd días (arranque: $(uptime -s))"; fi
  finding F1 INFO "Memoria RAM" "$(awk '/MemTotal/{printf "%.1f GB", $2/1048576}' /proc/meminfo)"
  finding F1 INFO "CPU" "$(nproc) vCPU - $(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}')"
  local fg; fg="$(free_gb /)"
  if [ "$fg" -lt "$MIN_FREE_GB" ]; then finding F1 RISK "Espacio libre /" "$fg GB (mínimo $MIN_FREE_GB GB)"
  elif [ "$fg" -lt $((MIN_FREE_GB*3/2)) ]; then finding F1 WARN "Espacio libre /" "$fg GB (mínimo $MIN_FREE_GB GB)"
  else finding F1 OK "Espacio libre /" "$fg GB"; fi
  if printf '%s' "$smart_txt" | grep -q 'no instalado'; then finding F1 INFO "SMART" "smartctl no instalado (apt install smartmontools para habilitarlo)"
  elif printf '%s' "$smart_txt" | grep -qiE 'FAILED'; then finding F1 RISK "SMART" "Disco con estado FAILED"
  elif printf '%s' "$smart_txt" | grep -qiE 'PASSED|OK'; then finding F1 OK "SMART" "PASSED"
  else finding F1 INFO "SMART" "Sin datos SMART (típico en VM)"; fi
  local nf; nf=$(wc -l < "$META/failed_before")
  if [ "$nf" -gt 0 ]; then finding F1 WARN "Servicios fallidos" "$(tr '\n' ' ' < "$META/failed_before")"; else finding F1 OK "Servicios fallidos" "Ninguno"; fi
  finding F1 INFO "Servicios" "Running=$(systemctl list-units --type=service --state=running --no-legend | wc -l) Enabled=$(systemctl list-unit-files --type=service --state=enabled --no-legend | wc -l) Disabled=$(systemctl list-unit-files --type=service --state=disabled --no-legend | wc -l)"
  local roles="" u
  for u in ssh docker containerd kubelet nginx apache2 mariadb mysql postgresql bind9 named isc-dhcp-server kea-dhcp4-server smbd nfs-server slapd libvirtd haproxy postfix keepalived xrdp; do
    unit_exists "$u" && roles="$roles $u"
  done
  mset roles "$roles"
  finding F1 INFO "Roles/servicios de servidor instalados" "${roles:-ninguno detectado}"
  finding F1 INFO "Paquetes" "$(wc -l < "$META/pkgs_before") paquetes dpkg; snaps: $(snap list 2>/dev/null | tail -n +2 | wc -l)"

  sec F1 EstadoInicial "- Hostname: $(hostname)${NL}- SO: $PRETTY_NAME, kernel $(uname -r)${NL}- Último arranque: $(uptime -s)${NL}- Espacio libre /: $fg GB"
  sec F1 Accion "Recolección de solo lectura (sin cambios en el servidor)."
  sec F1 Resultado "Inventario completo guardado en evidencias."
  sec F1 Validacion "Cada dato proviene de comandos ejecutados en el servidor (ver Evidencia)."
  sec F1 Rollback "No aplica (solo lectura)."
  sec F1 Recomendaciones "Contrastar el inventario con la documentación del servidor."
  sec F1 Conclusion "Línea base registrada."
}

# =============================================================================
# FASE 2 - PRE-CHECK
# =============================================================================
fase2() {
  CUR=F2; hdr "FASE 2 - PRE-CHECK DE PARCHEO"
  local fg fv fb h
  fg="$(free_gb /)"; fv="$(free_gb /var)"; fb="$(df -P -BM /boot 2>/dev/null | awk 'NR==2{gsub("M","",$4); print $4+0}')"
  ev espacio 'df -h / /var /boot 2>/dev/null; echo; df -i / /var 2>/dev/null'
  if [ "$fg" -ge "$MIN_FREE_GB" ]; then finding F2 OK "Espacio libre /" "$fg GB"; else finding F2 RISK "Espacio libre /" "$fg GB (mínimo $MIN_FREE_GB GB)"; fi
  if [ "$fv" -ge $((MIN_FREE_GB/2)) ]; then finding F2 OK "Espacio libre /var" "$fv GB"; else finding F2 WARN "Espacio libre /var" "$fv GB"; fi
  if [ -n "$fb" ]; then if [ "$fb" -ge 300 ]; then finding F2 OK "Espacio libre /boot" "$fb MB"; else finding F2 WARN "Espacio libre /boot" "$fb MB (kernels nuevos requieren espacio)"; fi; fi
  ev procesos_apt 'pgrep -a -x "apt|apt-get|dpkg|unattended-upgr|aptitude" || echo "ninguno"; ls -l /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock 2>&1'
  if evbody | grep -q 'ninguno'; then finding F2 OK "Bloqueos APT/dpkg" "Sin procesos de paquetes en curso"; else finding F2 RISK "Bloqueos APT/dpkg" "Hay procesos APT/dpkg en ejecución (ver evidencia)"; fi
  ev dpkg_audit 'dpkg --audit; echo "rc=$?"; apt-get check 2>&1; echo "apt-get check rc=$?"'
  if [ -z "$(evbody | grep -vE '^rc=|^Reading|^Building|^apt-get check rc=0$|^$')" ] && evbody | grep -q 'apt-get check rc=0'; then finding F2 OK "Estado de dpkg/APT" "dpkg --audit limpio; apt-get check correcto"
  else finding F2 RISK "Estado de dpkg/APT" "Paquetes inconsistentes (ver evidencia)"; fi
  ev paquetes_retenidos 'apt-mark showhold; echo "(fin)"'
  h="$(evbody | grep -v '^(fin)')"
  if [ -n "$h" ]; then finding F2 WARN "Paquetes retenidos (hold)" "$(echo $h)"; else finding F2 OK "Paquetes retenidos (hold)" "Ninguno"; fi
  ev sincronizacion_hora 'timedatectl; chronyc tracking 2>/dev/null'
  if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then finding F2 OK "Sincronización horaria" "NTP sincronizado"; else finding F2 WARN "Sincronización horaria" "NTP no sincronizado"; fi
  ev estado_systemd 'systemctl is-system-running; systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --no-pager'
  local sr; sr="$(systemctl is-system-running 2>/dev/null)"
  if [ "$sr" = "running" ]; then finding F2 OK "Estado de systemd" "running"; else finding F2 WARN "Estado de systemd" "$sr"; fi
  ev conectividad 'for h in archive.ubuntu.com security.ubuntu.com; do if timeout 8 bash -c "exec 3<>/dev/tcp/$h/443" 2>/dev/null; then echo "$h:443 OK"; else echo "$h:443 FALLA"; fi; getent hosts $h || echo "DNS $h FALLA"; done'
  if evbody | grep -q 'FALLA'; then finding F2 WARN "Conectividad a repositorios Ubuntu" "Falla (¿proxy o espejo local? ver evidencia)"; else finding F2 OK "Conectividad a repositorios Ubuntu" "archive/security.ubuntu.com:443 accesibles"; fi
  local rr; rr="$(reboot_reasons)"
  ev reinicio_pendiente 'ls -l /var/run/reboot-required* 2>&1; echo; command -v needrestart >/dev/null && needrestart -b -r l 2>&1 || echo "needrestart no instalado"'
  if [ -n "$rr" ]; then finding F2 WARN "Reinicio pendiente previo" "🟡 $rr"; else finding F2 OK "Reinicio pendiente previo" "🟢 No requiere reinicio"; fi
  mset reboot_before "$rr"
  sec F2 EstadoInicial "- Espacio libre /: $fg GB; /var: $fv GB${NL}- Reinicio pendiente previo: ${rr:-no}"
  sec F2 Accion "Verificaciones de solo lectura: espacio, locks APT/dpkg, consistencia dpkg, holds, hora, conectividad, estado de systemd y reinicio pendiente."
  sec F2 Resultado "Ver diagnóstico."
  sec F2 Validacion "Estado leído de dpkg, apt, systemd y /var/run/reboot-required."
  sec F2 Rollback "No aplica (solo lectura)."
  sec F2 Recomendaciones "Si hay reinicio pendiente previo, reiniciar antes de instalar. Tomar snapshot de la VM."
}

# =============================================================================
# FASE 3 - RESPALDOS
# =============================================================================
fase3() {
  CUR=F3; hdr "FASE 3 - RESPALDOS"
  local bk="$BACKUP/$RUN_ID"; umask 077; mkdir -p "$bk"; mset backup_dir "$bk"
  bkdo() { local n="$1"; shift; if ( "$@" ) >> "$bk/_errores.log" 2>&1; then finding F3 OK "$n" "Respaldo creado"; else finding F3 RISK "$n" "Falló (ver $bk/_errores.log)"; fi; }
  bkdo "/etc completo (tar.gz)" tar -czpf "$bk/etc.tar.gz" -C / etc
  bkdo "Firewall (ufw/iptables/nft)" bash -c "ufw status verbose > '$bk/ufw_status.txt' 2>&1; iptables-save > '$bk/iptables.rules' 2>&1; ip6tables-save > '$bk/ip6tables.rules' 2>&1; nft list ruleset > '$bk/nft_ruleset.txt' 2>&1; true"
  bkdo "Configuración de red" bash -c "ip addr > '$bk/ip_addr.txt'; ip route > '$bk/ip_route.txt'; resolvectl status > '$bk/resolvectl.txt' 2>&1; cp -a /etc/netplan '$bk/netplan' 2>/dev/null; netplan get > '$bk/netplan_get.yaml' 2>&1; true"
  bkdo "Servicios (systemd)" bash -c "systemctl list-unit-files --no-pager > '$bk/unit_files.txt'; systemctl list-units --all --no-pager > '$bk/units.txt'"
  bkdo "Tareas programadas (cron/timers)" bash -c "systemctl list-timers --all --no-pager > '$bk/timers.txt'; cp -a /var/spool/cron '$bk/spool_cron' 2>/dev/null; for u in \$(cut -d: -f1 /etc/passwd); do crontab -l -u \$u > '$bk/crontab_'\$u'.txt' 2>/dev/null || rm -f '$bk/crontab_'\$u'.txt'; done; true"
  bkdo "Políticas locales (sysctl/AppArmor/auditd/sudoers)" bash -c "sysctl -a > '$bk/sysctl_all.txt' 2>/dev/null; aa-status > '$bk/apparmor.txt' 2>&1; auditctl -l > '$bk/auditd_rules.txt' 2>&1; sshd -T > '$bk/sshd_T.txt' 2>&1; getent passwd > '$bk/passwd.txt'; getent group > '$bk/group.txt'; true"
  bkdo "Paquetes y repositorios" bash -c "dpkg --get-selections > '$bk/dpkg_selections.txt'; apt-mark showmanual > '$bk/apt_manual.txt'; apt-mark showhold > '$bk/apt_hold.txt'; cp '$META/pkgs_before' '$bk/pkgs_versiones.tsv'; snap list > '$bk/snap_list.txt' 2>&1; true"
  bkdo "GRUB y kernels" bash -c "ls -l /boot > '$bk/boot_listing.txt'; cp -a /boot/grub/grub.cfg '$bk/grub.cfg' 2>/dev/null; true"
  if unit_exists docker; then bkdo "Docker (inventario)" bash -c "docker ps -a > '$bk/docker_ps.txt' 2>&1; docker images > '$bk/docker_images.txt' 2>&1; docker volume ls > '$bk/docker_volumes.txt' 2>&1; true"; fi
  if unit_exists nginx || unit_exists apache2; then finding F3 INFO "Servidor web" "Configuración incluida en el respaldo de /etc"; fi
  # SHA256
  if ( cd "$bk" && find . -type f ! -name SHA256SUMS -print0 | xargs -0 sha256sum > SHA256SUMS ); then
    if ( cd "$bk" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1 ); then finding F3 OK "SHA256 de respaldos" "$(wc -l < "$bk/SHA256SUMS") archivos; verificación de integridad correcta"
    else finding F3 RISK "SHA256 de respaldos" "Verificación de integridad FALLÓ"; fi
  else finding F3 RISK "SHA256 de respaldos" "No se pudo generar SHA256SUMS"; fi
  evfile SHA256SUMS "$bk/SHA256SUMS" "sha256sum de todos los respaldos"
  evfile Carpeta_respaldo "$bk" "Respaldos de configuración"
  finding F3 INFO "Snapshot de VM" "Este script no crea snapshots del hipervisor; se recomienda uno antes de parchear"
  umask 022
  sec F3 EstadoInicial "Sin respaldo previo de esta corrida. Destino: $bk (permisos 700)."
  sec F3 Accion "Respaldo de /etc, firewall, red, servicios, tareas, políticas, paquetes/versiones, GRUB, Docker (si existe) y SHA256 con verificación."
  sec F3 Resultado "Ver diagnóstico."
  sec F3 Validacion "sha256sum -c sobre SHA256SUMS."
  sec F3 Rollback "- Configuración: ${BT}tar -xzpf $bk/etc.tar.gz -C /${BT}${NL}- Firewall: ${BT}iptables-restore < $bk/iptables.rules${BT} (o ufw según ufw_status.txt)${NL}- Paquete concreto: ${BT}apt-get install <paquete>=<versión anterior>${BT} (versiones en pkgs_versiones.tsv)${NL}- Kernel: seleccionar el kernel anterior en GRUB (Opciones avanzadas)${NL}- Último recurso: restaurar snapshot de la VM."
  sec F3 Recomendaciones "Copiar $bk fuera del servidor y tomar snapshot de la VM antes de parchear."
}

# =============================================================================
# FASE 4 - ACTUALIZACIONES (APT)
# =============================================================================
fase4() {
  CUR=F4; hdr "FASE 4 - ACTUALIZACIONES (APT)"
  local last d ep
  last="$(zgrep -h '^End-Date' /var/log/apt/history.log* 2>/dev/null | sed 's/End-Date: *//' | sort | tail -1)"
  if [ -n "$last" ]; then
    ep="$(date -d "${last/  / }" +%s 2>/dev/null)"; d=$(( ( $(date +%s) - ${ep:-0} ) / 86400 ))
    if [ -n "$ep" ] && [ "$d" -gt 45 ]; then finding F4 WARN "Fecha del último parche (APT)" "$last (hace $d días)"; else finding F4 OK "Fecha del último parche (APT)" "$last"; fi
  else finding F4 WARN "Fecha del último parche (APT)" "Sin historial en /var/log/apt"; fi
  ev apt_sources 'grep -rhE "^(deb |URIs:)" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null'
  local third; third="$(evbody | grep -vi ubuntu | sort -u)"
  if [ -n "$third" ]; then finding F4 WARN "Repositorios no-Ubuntu" "$(echo $third) (full-upgrade también actualizará estos paquetes)"; else finding F4 OK "Repositorios" "Solo repositorios Ubuntu"; fi
  ev apt_update 'apt-get update'
  if [ "$EVRC" -eq 0 ] && ! grep -qE '^(E:|W: Failed|Err:)' "$EVF"; then finding F4 OK "apt-get update" "Listas actualizadas"
  else finding F4 RISK "apt-get update" "Errores (exit=$EVRC): $(grep -E '^(E:|Err:|W: Failed)' "$EVF" | head -3 | tr '\n' ' ')"; mset wu_fail 1; fi
  ev simulacion_full_upgrade 'apt-get -s full-upgrade'
  grep '^Inst ' "$EVF" > "$META/pending_list"; grep '^Remv ' "$EVF" > "$META/remove_list"
  local np ns nr ker kept
  np=$(wc -l < "$META/pending_list"); ns=$(grep -c -- '-security' "$META/pending_list"); nr=$(wc -l < "$META/remove_list")
  ker=$(grep -cE '^Inst linux-(image|modules|headers)' "$META/pending_list")
  kept="$(awk '/kept back:/{f=1;next} /^[A-Za-z]/{f=0} f' "$EVF" | tr -s ' \n' ' ')"
  mset pending_count "$np"; mset pending_sec "$ns"; mset remove_count "$nr"
  ev actualizables 'apt list --upgradable 2>/dev/null'
  ev snap_pendientes 'snap refresh --list 2>&1 || true'
  ev ubuntu_security_status 'ubuntu-security-status 2>/dev/null || pro security-status 2>/dev/null || echo "herramienta no disponible"'
  if [ "$np" -gt 0 ]; then finding F4 WARN "Actualizaciones pendientes" "$np paquetes ($ns de seguridad, $ker de kernel)"; else finding F4 OK "Actualizaciones pendientes" "Ninguna"; fi
  while IFS= read -r l; do
    local pkg sev="actualización"; pkg="$(echo "$l" | awk '{print $2}')"; echo "$l" | grep -q -- '-security' && sev="SEGURIDAD"
    finding F4 INFO "Pendiente $pkg" "$sev | $(echo "$l" | sed 's/^Inst //' | cut -c1-110)"
  done < <(head -40 "$META/pending_list")
  [ "$np" -gt 40 ] && finding F4 INFO "Listado" "Se muestran 40 de $np; lista completa en evidencia"
  if [ "$nr" -gt 0 ]; then finding F4 WARN "Paquetes que serían ELIMINADOS" "$nr: $(awk '{print $2}' "$META/remove_list" | tr '\n' ' ')"; fi
  [ -n "$kept" ] && finding F4 INFO "Paquetes retenidos (kept back / phased updates)" "$kept"
  sec F4 EstadoInicial "- Último parche APT: ${last:-n/d}${NL}- Pendientes: $np (seguridad: $ns)"
  sec F4 Accion "apt-get update (solo repositorios configurados en el sistema) y simulación 'apt-get -s full-upgrade'. Severidad: Ubuntu no publica CVSS por paquete; se distingue origen '-security' vs '-updates'."
  sec F4 Resultado "Pendientes detectadas: $np; eliminaciones previstas: $nr."
  sec F4 Validacion "Listado tomado de la simulación de APT y de 'apt list --upgradable'."
  sec F4 Rollback "No se instaló nada en esta fase (solo apt-get update, que no altera paquetes)."
  sec F4 Recomendaciones "Revisar pendientes de seguridad y kernel antes de instalar."
}

# =============================================================================
# FASE 5 - INSTALACIÓN CONTROLADA (una única ejecución)
# =============================================================================
fase5() {
  CUR=F5; hdr "FASE 5 - INSTALACIÓN CONTROLADA"
  local np nr why=""
  np="$(mget pending_count)"; nr="$(mget remove_count)"
  [ "$SKIP_INSTALL" -eq 1 ] && why="parámetro --skip-install"
  [ -z "$why" ] && [ "$(mget wu_fail)" = "1" ] && why="fallo en apt-get update"
  [ -z "$why" ] && [ "${np:-0}" -eq 0 ] && why="no hay actualizaciones pendientes"
  [ -z "$why" ] && [ "${nr:-0}" -gt 0 ] && [ "$ALLOW_REMOVE" -eq 0 ] && why="full-upgrade eliminaría $nr paquete(s); use --allow-removals tras revisarlo"
  if [ -n "$why" ]; then
    finding F5 INFO "Instalación" "No ejecutada: $why"
    mset install_exec 0; : > "$META/installed_list"; : > "$META/failed_list"
    sec F5 EstadoInicial "Pendientes: ${np:-0}"; sec F5 Accion "Instalación omitida ($why)."; sec F5 Resultado "Sin cambios."
    sec F5 Validacion "n/a"; sec F5 Rollback "No aplica."; sec F5 Recomendaciones ""; return
  fi
  mset install_exec 1
  local t0 t1 log rc errs
  t0=$(date +%s); mset t0 "$t0"; log="$EV/F5_apt_full-upgrade.log"
  echo "  Instalando $np actualización(es) (única ejecución)..."
  apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300 full-upgrade 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  if [ "$INCLUDE_SNAP" -eq 1 ]; then snap refresh 2>&1 | tee -a "$log"; fi
  t1=$(date +%s); mset t1 "$t1"
  printf '%s\t%s\t%s\t%s\n' F5 apt_full-upgrade "apt-get -y full-upgrade (confdef+confold)" "$log" >> "$EVI"
  ev apt_history 'tail -n 60 /var/log/apt/history.log'
  ev dpkg_audit_post 'dpkg --audit; echo "rc=$?"'
  dpkg-query -W -f='${Package}\t${Version}\n' | sort > "$META/pkgs_after"
  awk -F'\t' 'NR==FNR{a[$1]=$2;next} ($1 in a)&&a[$1]!=$2{print $1": "a[$1]" -> "$2} !($1 in a){print $1": (nuevo) "$2}' "$META/pkgs_before" "$META/pkgs_after" > "$META/installed_list"
  errs="$(grep -E '^E:|dpkg: error|Errors were encountered|^Err:' "$log" | sort -u | head -10)"
  printf '%s\n' "$errs" | grep . > "$META/failed_list" || : > "$META/failed_list"
  mset install_rc "$rc"
  local ni; ni=$(wc -l < "$META/installed_list")
  finding F5 INFO "Hora de inicio / fin" "$(date -d @"$t0" +%T) / $(date -d @"$t1" +%T)"
  finding F5 INFO "Tiempo total" "$(fmt_dur $((t1-t0)))"
  if [ "$ni" -gt 0 ]; then finding F5 OK "Paquetes actualizados/instalados" "$ni"; else finding F5 WARN "Paquetes actualizados/instalados" "0"; fi
  if [ "$rc" -ne 0 ] || [ -s "$META/failed_list" ]; then finding F5 RISK "Errores durante la instalación" "apt-get exit=$rc. $(tr '\n' ' ' < "$META/failed_list")"
  else finding F5 OK "Errores durante la instalación" "Sin errores (apt-get exit=0)"; fi
  sec F5 EstadoInicial "Pendientes antes de instalar: $np"
  sec F5 Accion "apt-get -y full-upgrade con --force-confdef --force-confold (conserva configuraciones locales), ejecución única, $(date -d @"$t0" +%T) - $(date -d @"$t1" +%T)."
  sec F5 Resultado "Paquetes cambiados: $ni. Código de salida: $rc.${NL}$(sed 's/^/- /' "$META/installed_list" | head -80)"
  sec F5 Validacion "Comparación de versiones dpkg antes/después y revisión de salida de APT."
  sec F5 Rollback "- Versión puntual: ${BT}apt-get install <paquete>=<versión anterior>${BT} (ver pkgs_versiones.tsv en el respaldo)${NL}- Kernel: arrancar el kernel anterior desde GRUB${NL}- Reparar dpkg: ${BT}dpkg --configure -a${BT} y ${BT}apt-get -f install${BT}${NL}- Último recurso: snapshot de VM."
  sec F5 Recomendaciones "$([ "$rc" -ne 0 ] && echo 'Revisar /var/log/apt/term.log y /var/log/dpkg.log.')"
}

# =============================================================================
# FASE 6 - REINICIO CONTROLADO
# =============================================================================
fase6_prepare() {   # return 0 si se requiere reinicio
  CUR=F6; hdr "FASE 6 - REINICIO CONTROLADO"
  local rr; rr="$(reboot_reasons)"
  ev needrestart 'command -v needrestart >/dev/null && needrestart -b -r l 2>&1 || echo "needrestart no instalado"'
  local svcs; svcs="$(grep '^NEEDRESTART-SVC' "$EVF" | sed 's/NEEDRESTART-SVC: //' | tr '\n' ' ')"
  [ -n "$svcs" ] && finding F6 WARN "Servicios que requieren reinicio (sin reiniciar el SO)" "$svcs"
  if [ -z "$rr" ]; then finding F6 OK "Reinicio requerido" "🟢 No requiere reinicio"; mset reboot_needed 0; return 1; fi
  finding F6 WARN "Reinicio requerido" "🟡 $rr"
  mset reboot_needed 1; mset reboot_reason "$rr"; mset reboot_decided "$(date +%s)"
  sec F6 EstadoInicial "Reinicio pendiente. Motivo: $rr"
  if [ "$AUTO_REBOOT" -eq 1 ]; then sec F6 Accion "Se crea el servicio patchmgmt-continue.service y se ejecuta 'shutdown -r +1'."
  else sec F6 Accion "Reinicio NO automático (falta --auto-reboot): la corrida queda en pausa."; fi
  sec F6 Resultado "Hora de decisión: $(date '+%F %T'). Impacto: el servidor y sus servicios (incluidos contenedores y roles listados en F1) quedan fuera de servicio durante el reinicio (estimado 2-10 min)."
  sec F6 Validacion "Tras el arranque: uname -r, systemctl --failed, ss -tulpn, ping localhost, comparación de contenedores."
  sec F6 Rollback "Cancelar reinicio programado: ${BT}shutdown -c${BT}; quitar continuación: ${BT}systemctl disable --now patchmgmt-continue.service && rm /etc/systemd/system/patchmgmt-continue.service${BT}."
  sec F6 Recomendaciones "Confirmar que no hay usuarios ni tareas críticas antes de reiniciar."
  return 0
}

fase6_validate() {
  CUR=F6; hdr "FASE 6 - VALIDACIÓN (post-reinicio / estado actual)"
  if [ "$CONTINUE" -eq 1 ] && [ "$(mget reboot_needed)" = "1" ]; then
    local n=0 jobs
    while [ $n -lt 18 ]; do jobs=$(systemctl list-jobs --no-legend 2>/dev/null | grep -vc patchmgmt-continue); [ "$jobs" -eq 0 ] && break; sleep 10; n=$((n+1)); done
    local boot dec down; boot=$(date -d "$(uptime -s)" +%s); dec="$(mget reboot_decided)"; down=$(( $(date +%s) - ${dec:-$boot} ))
    mset downtime "$(fmt_dur $down)"
    finding F6 INFO "Tiempo hasta servidor operativo" "$(fmt_dur $down) desde la decisión de reinicio (arranque: $(uptime -s))"
    if [ "$boot" -gt "${dec:-0}" ]; then finding F6 OK "Reinicio efectuado" "Arranque posterior a la decisión; kernel $(uname -r) (antes: $(mget kernel_before))"
    else finding F6 RISK "Reinicio efectuado" "El servidor NO se reinició"; fi
    systemctl disable patchmgmt-continue.service >/dev/null 2>&1; rm -f /etc/systemd/system/patchmgmt-continue.service; systemctl daemon-reload
  fi
  ev post_uname_uptime 'uname -a; uptime; hostnamectl'
  ev post_servicios_failed 'systemctl --failed --no-pager; systemctl is-system-running'
  ev post_puertos 'ss -tulpn'
  ev post_ping_localhost 'ping -c 3 localhost'
  if [ "$EVRC" -eq 0 ]; then finding F6 OK "Ping localhost" "Respuesta correcta"; else finding F6 WARN "Ping localhost" "Sin respuesta (ver evidencia)"; fi
  local nf; nf=$(systemctl --failed --no-legend --plain | wc -l)
  if [ "$nf" -gt 0 ]; then finding F6 WARN "Servicios fallidos (post)" "$(systemctl --failed --no-legend --plain | awk '{print $1}' | tr '\n' ' ')"; else finding F6 OK "Servicios fallidos (post)" "Ninguno"; fi
  local rr; rr="$(reboot_reasons)"
  if [ -n "$rr" ]; then finding F6 WARN "Reinicio pendiente (post)" "$rr"; else finding F6 OK "Reinicio pendiente (post)" "No requiere reinicio"; fi
  if [ ! -s "$SEC/F6.EstadoInicial" ]; then
    sec F6 EstadoInicial "Sin reinicio requerido tras la instalación."; sec F6 Accion "Solo validación."
    sec F6 Resultado "Sin indisponibilidad."; sec F6 Validacion "uname, systemctl, ss, ping."; sec F6 Rollback "No aplica."; sec F6 Recomendaciones ""
  else
    sec F6 Resultado "$(cat "$SEC/F6.Resultado")${NL}Tiempo de indisponibilidad medido: $(mget downtime)."
  fi
}

# =============================================================================
# FASE 7 - VALIDACIÓN POSTERIOR
# =============================================================================
fase7() {
  CUR=F7; hdr "FASE 7 - VALIDACIÓN POSTERIOR"
  dpkg-query -W -f='${Package}\t${Version}\n' | sort > "$META/pkgs_final"
  awk -F'\t' 'NR==FNR{a[$1]=$2;next} ($1 in a)&&a[$1]!=$2{print $1": "a[$1]" -> "$2} !($1 in a){print $1": (nuevo) "$2} END{}' "$META/pkgs_before" "$META/pkgs_final" > "$EV/F7_comparacion_antes_despues.txt"
  awk -F'\t' 'NR==FNR{a[$1]=1;next} !($1 in a){print "ELIMINADO: "$1}' "$META/pkgs_final" "$META/pkgs_before" >> "$EV/F7_comparacion_antes_despues.txt"
  evfile comparacion_antes_despues "$EV/F7_comparacion_antes_despues.txt" "dpkg-query antes vs después (diff de versiones)"
  local ch; ch=$(wc -l < "$EV/F7_comparacion_antes_despues.txt")
  finding F7 INFO "Paquetes antes vs después" "Antes=$(wc -l < "$META/pkgs_before") Después=$(wc -l < "$META/pkgs_final") Cambios=$ch"
  finding F7 INFO "Kernel" "Antes: $(mget kernel_before) | En ejecución: $(uname -r)"
  local ok fl; ok=$(wc -l < "$META/installed_list" 2>/dev/null); fl=$(wc -l < "$META/failed_list" 2>/dev/null)
  finding F7 INFO "Actualizaciones exitosas" "${ok:-0}"
  if [ "${fl:-0}" -gt 0 ] || [ "$(mget install_rc)" -gt 0 ] 2>/dev/null; then finding F7 RISK "Actualizaciones fallidas" "$fl error(es), exit=$(mget install_rc)"; else finding F7 OK "Actualizaciones fallidas" "0"; fi
  ev reescaneo 'apt-get -s full-upgrade'
  local p2; p2=$(grep -c '^Inst ' "$EVF"); mset pending_after "$p2"
  if [ "$p2" -gt 0 ]; then finding F7 WARN "Pendientes tras la instalación" "$p2 (posibles phased updates o nuevo ciclo requerido)"; else finding F7 OK "Pendientes tras la instalación" "Ninguna"; fi
  ev dpkg_audit_final 'dpkg --audit; echo "rc=$?"'
  if [ -z "$(evbody | grep -v '^rc=')" ]; then finding F7 OK "Consistencia dpkg" "Sin paquetes rotos"; else finding F7 RISK "Consistencia dpkg" "Paquetes en estado inconsistente"; fi
  local nb; nb=$(comm -13 "$META/failed_before" <(systemctl --failed --no-legend --plain | awk '{print $1}' | sort) | tr '\n' ' ')
  if [ -n "$nb" ]; then finding F7 RISK "Servicios fallidos nuevos vs inicio" "$nb"; else finding F7 OK "Servicios fallidos nuevos vs inicio" "Ninguno"; fi
  sec F7 EstadoInicial "Paquetes antes: $(wc -l < "$META/pkgs_before")"
  sec F7 Accion "Comparación de versiones dpkg, re-simulación de full-upgrade, dpkg --audit y servicios fallidos (sin instalar de nuevo)."
  sec F7 Resultado "Cambios: $ch. Pendientes: $p2."
  sec F7 Validacion "Listas dpkg antes/después y simulación APT."
  sec F7 Rollback "apt-get install <paquete>=<versión anterior> (ver pkgs_versiones.tsv)."
  sec F7 Recomendaciones "$([ "$p2" -gt 0 ] && echo 'Programar un nuevo ciclo controlado (la instalación se ejecuta una sola vez por corrida).')"
}

# =============================================================================
# FASE 8 - HARDENING POSTERIOR (verificación)
# =============================================================================
fase8() {
  CUR=F8; hdr "FASE 8 - HARDENING POSTERIOR"
  local acc=""
  # Firewall
  ev firewall 'ufw status verbose 2>&1; echo; nft list ruleset 2>&1 | head -80; echo; iptables -S 2>&1 | head -40'
  if ufw status 2>/dev/null | grep -q 'Status: active'; then finding F8 OK "Firewall" "UFW activo"
  elif nft list ruleset 2>/dev/null | grep -q 'chain'; then finding F8 WARN "Firewall" "UFW inactivo pero hay reglas nftables/iptables (verificar)"
  else finding F8 RISK "Firewall" "Sin firewall activo (ufw inactivo y sin reglas nft)"; fi
  # AppArmor
  ev apparmor 'aa-status 2>&1'
  if aa-status --enabled 2>/dev/null; then finding F8 OK "AppArmor" "$(grep -E 'profiles are in enforce mode' "$EVF" | head -1 | sed 's/^ *//')"; else finding F8 RISK "AppArmor" "No habilitado"; fi
  # Actualizaciones automáticas
  ev auto_updates 'apt-config dump APT::Periodic; systemctl is-enabled unattended-upgrades 2>&1; systemctl is-active unattended-upgrades 2>&1'
  if grep -q 'Unattended-Upgrade "1"' "$EVF"; then finding F8 OK "Actualizaciones de seguridad automáticas" "unattended-upgrades habilitado"; else finding F8 WARN "Actualizaciones de seguridad automáticas" "unattended-upgrades no habilitado"; fi
  # Auditoría
  ev auditoria 'systemctl is-active auditd 2>&1; auditctl -s 2>&1; auditctl -l 2>&1'
  if systemctl is-active --quiet auditd; then
    local nr; nr=$(auditctl -l 2>/dev/null | grep -vc 'No rules'); finding F8 OK "Auditoría (auditd)" "Activo; $nr reglas"
  else finding F8 WARN "Auditoría (auditd)" "auditd no activo/instalado (recomendado por CIS)"; fi
  # SSH
  ev sshd_config 'sshd -T 2>&1'
  if command -v sshd >/dev/null; then
    local t; t="$(grep -v '^# ' "$EVF")"
    sshv() { echo "$t" | awk -v k="$1" '$1==k{ $1=""; sub(/^ /,""); print; exit }'; }
    local prl pa pk x11 mat pe
    prl="$(sshv permitrootlogin)"; pa="$(sshv passwordauthentication)"; pk="$(sshv pubkeyauthentication)"; x11="$(sshv x11forwarding)"; mat="$(sshv maxauthtries)"; pe="$(sshv permitemptypasswords)"
    case "$prl" in no|prohibit-password|without-password) finding F8 OK "SSH PermitRootLogin" "$prl";; *) finding F8 RISK "SSH PermitRootLogin" "$prl";; esac
    if [ "$pa" = "yes" ]; then finding F8 WARN "SSH PasswordAuthentication" "yes (preferir solo claves)"; else finding F8 OK "SSH PasswordAuthentication" "$pa"; fi
    [ "$pk" = "yes" ] && finding F8 OK "SSH PubkeyAuthentication" "yes" || finding F8 WARN "SSH PubkeyAuthentication" "$pk"
    [ "$pe" = "no" ] && finding F8 OK "SSH PermitEmptyPasswords" "no" || finding F8 RISK "SSH PermitEmptyPasswords" "$pe"
    finding F8 INFO "SSH X11Forwarding / MaxAuthTries" "$x11 / $mat"
    if echo "$t" | grep -E '^(ciphers|macs|kexalgorithms) ' | grep -qiE 'cbc|3des|md5|sha1,|hmac-sha1( |,|$)'; then finding F8 WARN "SSH algoritmos débiles" "Se detectan CBC/3DES/SHA1 en la configuración efectiva"; else finding F8 OK "SSH algoritmos" "Sin CBC/3DES/MD5 en la configuración efectiva"; fi
  else finding F8 INFO "SSH" "sshd no instalado"; fi
  # TLS / criptografía del sistema
  ev tls_openssl 'openssl version; grep -nE "MinProtocol|CipherString|MaxProtocol" /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.d/* 2>/dev/null; echo; update-crypto-policies --show 2>/dev/null || true'
  local port; local tlsout=""
  for port in $(ss -ltn 2>/dev/null | awk 'NR>1{n=split($4,a,":"); print a[n]}' | sort -un | grep -E '^(443|8443|993|995|636|465|5432|3306)$'); do
    local r12 r13 r11
    r12=$(timeout 6 openssl s_client -connect 127.0.0.1:$port -tls1_2 </dev/null 2>&1 | grep -c 'Cipher is\|Protocol *: TLSv1.2')
    r13=$(timeout 6 openssl s_client -connect 127.0.0.1:$port -tls1_3 </dev/null 2>&1 | grep -c 'Protocol *: TLSv1.3')
    r11=$(timeout 6 openssl s_client -connect 127.0.0.1:$port -tls1_1 </dev/null 2>&1 | grep -c 'Protocol *: TLSv1.1')
    tlsout="$tlsout puerto $port: TLS1.2=$([ "$r12" -gt 0 ] && echo sí || echo no) TLS1.3=$([ "$r13" -gt 0 ] && echo sí || echo no) TLS1.1=$([ "$r11" -gt 0 ] && echo SÍ || echo no);"
    [ "$r11" -gt 0 ] && finding F8 RISK "TLS 1.1 aceptado en puerto $port" "Protocolo inseguro habilitado"
  done
  evtext_tls() { printf '%s\n' "$tlsout" > "$EV/F8_tls_puertos_locales.txt"; evfile tls_puertos_locales "$EV/F8_tls_puertos_locales.txt" "openssl s_client -tls1_1/-tls1_2/-tls1_3 a puertos TLS locales"; }; evtext_tls
  finding F8 INFO "TLS (puertos locales)" "${tlsout:-Sin servicios TLS comunes en escucha local}"
  # SMB / NFS
  if command -v testparm >/dev/null; then
    ev samba 'testparm -sv 2>/dev/null | grep -iE "min protocol|max protocol|server signing|client signing"'
    if grep -qiE 'min protocol *= *(NT1|LANMAN|CORE|COREPLUS)' "$EVF"; then finding F8 RISK "Samba (SMBv1)" "server min protocol permite SMBv1 (NT1)"; else finding F8 OK "Samba" "SMBv1 no permitido ($(grep -i 'min protocol' "$EVF" | head -1 | tr -s ' '))"; fi
  else finding F8 INFO "Samba/SMB" "No instalado"; fi
  ev nfs 'exportfs -v 2>&1 | head -30'
  # sudo / privilegios (equivalente a UAC)
  ev sudo_config 'sudo --version 2>&1 | head -2; echo; getent group sudo; getent group adm; echo; grep -rnE "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; echo; visudo -c 2>&1'
  local np; np=$(grep -c 'NOPASSWD' "$EVF")
  if [ "$np" -gt 0 ]; then finding F8 WARN "sudo NOPASSWD" "$np entrada(s) NOPASSWD (ver evidencia)"; else finding F8 OK "sudo NOPASSWD" "Sin entradas NOPASSWD"; fi
  finding F8 INFO "Implementación de sudo" "$(sudo --version 2>/dev/null | head -1)"
  # cuentas
  ev cuentas 'awk -F: "(\$3==0){print \"UID0: \"\$1}" /etc/passwd; awk -F: "(\$2==\"\"){print \"SIN CONTRASENA: \"\$1}" /etc/shadow; getent passwd | awk -F: "\$7 !~ /(nologin|false)\$/ {print \$1\" (\"\$7\")\"}"; echo; lastlog -b 0 2>/dev/null | head -20; echo; last -n 15'
  local u0; u0=$(grep -c '^UID0:' "$EVF")
  if [ "$u0" -gt 1 ]; then finding F8 RISK "Cuentas UID 0" "Hay $u0 cuentas con UID 0"; else finding F8 OK "Cuentas UID 0" "Solo root"; fi
  if grep -q '^SIN CONTRASENA' "$EVF"; then finding F8 RISK "Cuentas sin contraseña" "$(grep '^SIN CONTRASENA' "$EVF" | tr '\n' ' ')"; else finding F8 OK "Cuentas sin contraseña" "Ninguna"; fi
  # acceso remoto alternativo (equivalente a RDP)
  if unit_exists xrdp; then finding F8 WARN "xrdp" "Instalado ($(systemctl is-active xrdp)); revisar NLA/alcance y usuarios autorizados"; else finding F8 OK "Escritorio remoto (xrdp)" "No instalado"; fi
  # kernel / sysctl
  ev sysctl_seguridad 'sysctl kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.tcp_syncookies net.ipv4.ip_forward fs.protected_hardlinks fs.protected_symlinks 2>&1'
  [ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" = "2" ] && finding F8 OK "ASLR" "kernel.randomize_va_space=2" || finding F8 RISK "ASLR" "kernel.randomize_va_space=$(sysctl -n kernel.randomize_va_space)"
  [ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" = "1" ] && finding F8 OK "SYN cookies" "habilitadas" || finding F8 WARN "SYN cookies" "deshabilitadas"
  [ "$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)" = "0" ] || finding F8 WARN "ICMP redirects" "accept_redirects distinto de 0"
  # Ubuntu Pro / Livepatch
  ev ubuntu_pro 'pro status 2>&1 | head -25'
  # Aplicar hardening reversible
  if [ "$APPLY_HARD" -eq 1 ]; then
    local f=/etc/sysctl.d/99-patchmgmt-hardening.conf
    cat > "$f" <<'SYSCTL'
# Patch Management - hardening reversible (borrar este archivo y ejecutar sysctl --system para revertir)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
SYSCTL
    if sysctl --system >/dev/null 2>&1; then finding F8 OK "Hardening sysctl aplicado" "$f"; acc="Se creó $f."; else finding F8 RISK "Hardening sysctl" "Error al aplicar"; fi
    evfile sysctl_dropin "$f" "cat > $f"
  fi
  sec F8 EstadoInicial "Configuración de seguridad leída directamente del servidor."
  sec F8 Accion "Verificación de firewall, AppArmor, auditd, SSH, TLS/OpenSSL, Samba/NFS, sudo, cuentas, xrdp y sysctl. $acc"
  sec F8 Resultado "Ver diagnóstico. Sin cambios salvo --apply-hardening (drop-in sysctl reversible)."
  sec F8 Validacion "Relectura de la configuración efectiva (sshd -T, sysctl, aa-status, ufw/nft)."
  sec F8 Rollback "sysctl: ${BT}rm /etc/sysctl.d/99-patchmgmt-hardening.conf && sysctl --system${BT}. Resto: sin cambios (respaldo en $(mget backup_dir))."
  sec F8 Recomendaciones "Contrastar contra CIS Ubuntu Linux Benchmark y Ubuntu Security Guide (USG) en un entorno de pruebas antes de aplicar cambios masivos. No se modifica SSH ni UFW automáticamente para evitar bloqueos de acceso."
}

# =============================================================================
# FASE 9 - LOGS (journald)
# =============================================================================
fase9() {
  CUR=F9; hdr "FASE 9 - LOGS DEL SISTEMA"
  local since="-${EVENT_DAYS} days"
  jc() { journalctl --no-pager -q -o short-iso --since "$since" "$@" 2>/dev/null; }
  cnt() { jc -g "$1" | wc -l; }
  local ok fail priv newu cfg svcf svcs
  ok=$(cnt 'Accepted (password|publickey|keyboard-interactive)')
  fail=$(cnt 'Failed password|Invalid user|authentication failure|Failed publickey')
  priv=$(cnt 'COMMAND=|session opened for user root')
  newu=$(cnt 'new user: name=|new group: name=')
  cfg=$( { jc _TRANSPORT=audit -g 'CONFIG_CHANGE'; ausearch -m CONFIG_CHANGE --start "$(date -d "$since" '+%m/%d/%Y %H:%M:%S')" 2>/dev/null; } | wc -l)
  svcf=$(cnt 'Failed with result|entered failed state|Main process exited, code=(exited|killed|dumped)')
  svcs=$(jc _PID=1 -g '^(Started|Stopped) ' | wc -l)
  {
    echo "Ventana: $since"
    echo "Equivalencias con Windows: 4624=Accepted SSH | 4625=Failed/Invalid | 4672=sudo/root | 4720=useradd/groupadd | 4719=CONFIG_CHANGE auditd | 7031=Failed with result | 7036=Started/Stopped"
    printf '%-45s %s\n' "Accepted (inicios de sesión SSH)" "$ok" "Failed/Invalid (fallos de autenticación)" "$fail" "sudo/root (uso de privilegios)" "$priv" "Cuentas/grupos creados" "$newu" "Cambios de auditoría (CONFIG_CHANGE)" "$cfg" "Servicios con fallo" "$svcf" "Servicios iniciados/detenidos" "$svcs"
  } > "$EV/F9_resumen_ids.txt"
  evfile resumen_ids "$EV/F9_resumen_ids.txt" "journalctl -g <patrón> --since '$since' (conteos)"
  jc -g 'Failed password|Invalid user|authentication failure|Failed publickey' | grep -oE '(from|rhost=) ?[0-9a-fA-F:.]+' | sed 's/rhost=//; s/from //' | sort | uniq -c | sort -rn | head -10 > "$EV/F9_top_origenes_fallos.txt"
  evfile top_origenes_fallos "$EV/F9_top_origenes_fallos.txt" "Top orígenes de fallos de autenticación"
  jc -g 'new user: name=' > "$EV/F9_cuentas_creadas.txt"; evfile cuentas_creadas "$EV/F9_cuentas_creadas.txt" "journalctl -g 'new user: name='"
  jc -g 'COMMAND=' | tail -200 > "$EV/F9_sudo_comandos.txt"; evfile sudo_comandos "$EV/F9_sudo_comandos.txt" "journalctl -g 'COMMAND=' (últimos 200)"
  jc -g 'Failed with result|entered failed state|Main process exited, code=(exited|killed|dumped)' > "$EV/F9_servicios_fallos.txt"; evfile servicios_fallos "$EV/F9_servicios_fallos.txt" "journalctl -g 'Failed with result...'"
  finding F9 INFO "Inicios de sesión SSH correctos (4624)" "$ok"
  local e=OK; [ "$fail" -gt 20 ] && e=WARN; [ "$fail" -gt 100 ] && e=RISK
  finding F9 "$e" "Autenticaciones fallidas (4625)" "$fail$([ -s "$EV/F9_top_origenes_fallos.txt" ] && echo " | top: $(head -3 "$EV/F9_top_origenes_fallos.txt" | sed 's/^ *//' | tr '\n' ';')")"
  finding F9 INFO "Uso de privilegios sudo/root (4672)" "$priv"
  [ "$cfg" -gt 0 ] && finding F9 WARN "Cambios de política de auditoría (4719)" "$cfg" || finding F9 OK "Cambios de política de auditoría (4719)" "0"
  [ "$newu" -gt 0 ] && finding F9 WARN "Cuentas/grupos creados (4720)" "$newu: $(grep -oE 'name=[^,]+' "$EV/F9_cuentas_creadas.txt" | sort -u | tr '\n' ' ')" || finding F9 OK "Cuentas/grupos creados (4720)" "0"
  [ "$svcf" -gt 0 ] && finding F9 WARN "Servicios con fallo (7031)" "$svcf" || finding F9 OK "Servicios con fallo (7031)" "0"
  finding F9 INFO "Cambios de estado de servicios (7036)" "$svcs"
  local nerr ncrit top
  nerr=$(journalctl --no-pager -q --since "-24h" -p 0..3 2>/dev/null | wc -l); ncrit=$(journalctl --no-pager -q --since "-24h" -p 0..2 2>/dev/null | wc -l)
  journalctl --no-pager -q -o short-iso --since "-24h" -p 0..3 2>/dev/null > "$EV/F9_errores_24h.txt"; evfile errores_24h "$EV/F9_errores_24h.txt" "journalctl -p 0..3 --since -24h"
  top="$(awk '{print $3}' "$EV/F9_errores_24h.txt" | sed 's/\[.*//; s/:$//' | sort | uniq -c | sort -rn | head -3 | sed 's/^ *//' | tr '\n' ';')"
  if [ "$ncrit" -gt 0 ]; then finding F9 RISK "journald (24 h) críticos/errores" "Críticos=$ncrit Errores totales=$nerr | top: $top"
  elif [ "$nerr" -gt 0 ]; then finding F9 WARN "journald (24 h) críticos/errores" "Errores=$nerr | top: $top"
  else finding F9 OK "journald (24 h) críticos/errores" "Sin errores"; fi
  ev kernel_errores 'dmesg --level=emerg,alert,crit,err 2>&1 | tail -40; echo; journalctl -k --no-pager -q --since -24h -g "Out of memory|oom-kill|segfault|I/O error|EXT4-fs error|Call Trace" 2>&1 | tail -30'
  if grep -qiE 'Out of memory|oom-kill|I/O error|EXT4-fs error|Call Trace' "$EVF"; then finding F9 WARN "Kernel (OOM/I-O/trace)" "Se detectaron mensajes relevantes (ver evidencia)"; else finding F9 OK "Kernel (OOM/I-O/trace)" "Sin mensajes relevantes"; fi
  sec F9 EstadoInicial "Ventana de análisis: $EVENT_DAYS días (errores: 24 h)."
  sec F9 Accion "Lectura de journald (equivalencias de Event IDs de Windows ver evidencia resumen_ids) y dmesg."
  sec F9 Resultado "Resumen técnico en el diagnóstico; extractos completos en evidencias."
  sec F9 Validacion "Conteos obtenidos con journalctl -g sobre los registros reales."
  sec F9 Rollback "No aplica (solo lectura)."
  sec F9 Recomendaciones "Investigar picos de fallos SSH, cuentas creadas no planificadas y servicios que fallan. Considerar fail2ban/ufw limit para SSH."
}

# =============================================================================
# FASE 10 - VALIDACIÓN OPERATIVA
# =============================================================================
fase10() {
  CUR=F10; hdr "FASE 10 - VALIDACIÓN OPERATIVA"
  local u s roles; roles="$(mget roles)"
  for u in systemd-journald systemd-logind dbus cron rsyslog ssh systemd-timesyncd chrony systemd-resolved systemd-networkd NetworkManager apparmor ufw auditd unattended-upgrades; do
    unit_exists "$u" || continue
    s="$(systemctl is-active "$u" 2>/dev/null)"
    if [ "$s" = "active" ]; then finding F10 OK "Servicio crítico $u" "active"
    elif systemctl is-enabled "$u" 2>/dev/null | grep -qE 'disabled|masked'; then finding F10 INFO "Servicio $u" "$s (deshabilitado)"
    else finding F10 WARN "Servicio crítico $u" "$s"; fi
  done
  for u in $roles; do
    s="$(systemctl is-active "$u" 2>/dev/null)"
    if [ "$s" = "active" ]; then finding F10 OK "Rol/servicio $u" "active"
    elif systemctl is-enabled "$u" 2>/dev/null | grep -qE '^enabled'; then finding F10 RISK "Rol/servicio $u" "$s (está habilitado y no corre)"
    else finding F10 INFO "Rol/servicio $u" "$s (no habilitado)"; fi
  done
  echo "$roles" | grep -qw docker && {
    ev docker 'docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"; echo; docker info 2>&1 | head -20'
    docker ps --format '{{.Names}}' 2>/dev/null | sort > "$META/ctr_after"
    local lost; lost="$(comm -23 "$META/ctr_before" "$META/ctr_after" | tr '\n' ' ')"
    if [ -n "$lost" ]; then finding F10 RISK "Contenedores que corrían antes y ya no" "$lost"; else finding F10 OK "Contenedores" "Los $(wc -l < "$META/ctr_before") contenedores iniciales siguen en ejecución"; fi
  }
  echo "$roles" | grep -qw nginx && { ev nginx_test 'nginx -t 2>&1'; [ "$EVRC" -eq 0 ] && finding F10 OK "nginx -t" "Configuración válida" || finding F10 RISK "nginx -t" "Configuración inválida"; }
  echo "$roles" | grep -qw apache2 && { ev apache_test 'apache2ctl configtest 2>&1'; grep -q 'Syntax OK' "$EVF" && finding F10 OK "apache2ctl configtest" "Syntax OK" || finding F10 RISK "apache2ctl configtest" "Revisar configuración"; }
  (echo "$roles" | grep -qwE 'bind9|named') && { ev bind_test 'named-checkconf 2>&1; echo "rc=$?"'; grep -q 'rc=0' "$EVF" && finding F10 OK "named-checkconf" "Configuración válida" || finding F10 RISK "named-checkconf" "Revisar configuración"; }
  echo "$roles" | grep -qw smbd && { ev samba_shares 'testparm -s 2>&1 | head -40'; finding F10 INFO "Samba - recursos compartidos" "Ver evidencia"; }
  echo "$roles" | grep -qw nfs-server && { ev nfs_exports 'exportfs -v 2>&1'; finding F10 INFO "NFS - exportaciones" "Ver evidencia"; }
  (echo "$roles" | grep -qwE 'mariadb|mysql') && { ev mysql_ping 'mysqladmin ping 2>&1'; grep -q 'alive' "$EVF" && finding F10 OK "MySQL/MariaDB" "mysqld is alive" || finding F10 WARN "MySQL/MariaDB" "mysqladmin ping sin respuesta (¿requiere credenciales?)"; }
  echo "$roles" | grep -qw postgresql && { ev pg_ready 'pg_isready 2>&1'; grep -q 'accepting' "$EVF" && finding F10 OK "PostgreSQL" "accepting connections" || finding F10 WARN "PostgreSQL" "$(evbody | head -1)"; }
  [ -z "$roles" ] && finding F10 INFO "Roles de servidor" "No se detectaron servicios de aplicación: solo se validaron servicios críticos del SO"
  ev puertos_post 'ss -tulpn'
  sec F10 EstadoInicial "Servicios/roles detectados en F1:${roles:- ninguno}"
  sec F10 Accion "Validación de servicios críticos y de los roles realmente instalados (sin asumir servicios inexistentes)."
  sec F10 Resultado "Ver diagnóstico."
  sec F10 Validacion "Estado de systemd, pruebas de configuración (nginx -t, apache2ctl configtest, named-checkconf) y comparación de contenedores antes/después."
  sec F10 Rollback "No aplica (solo lectura)."
  sec F10 Recomendaciones "Para servicios que usan librerías actualizadas y no se reiniciaron, revisar needrestart y reiniciarlos en ventana controlada."
}

# =============================================================================
# FASE 11 - HEALTH CHECK
# =============================================================================
fase11() {
  CUR=F11; hdr "FASE 11 - HEALTH CHECK"
  cat > "$HC_SCRIPT" <<'HCEOF'
#!/usr/bin/env bash
# patchmgmt-healthcheck.sh - generado por patch-management-ubuntu.sh (cada 5 minutos)
export LC_ALL=C.UTF-8
D=/var/log/patchmgmt; mkdir -p "$D"
CH=()
add() { CH+=("$1|$2|$3"); }
hi() { awk -v v="$1" -v w="$2" -v r="$3" 'BEGIN{ if(v>=r)print "RISK"; else if(v>=w)print "WARN"; else print "OK" }'; }
lo() { awk -v v="$1" -v w="$2" -v r="$3" 'BEGIN{ if(v<=r)print "RISK"; else if(v<=w)print "WARN"; else print "OK" }'; }
# CPU
read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ < /proc/stat; sleep 1; read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat
busy=$(( (u2+n2+s2+q2+sq2+st2) - (u1+n1+s1+q1+sq1+st1) )); idle=$(( (i2+w2) - (i1+w1) )); tot=$((busy+idle)); cpu=$(( tot>0 ? 100*busy/tot : 0 ))
add CPU "$(hi $cpu 75 90)" "${cpu}% (load: $(cut -d' ' -f1-3 /proc/loadavg), $(nproc) vCPU)"
# RAM
ram=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf "%.1f", (1-a/t)*100}' /proc/meminfo)
add RAM "$(hi "$ram" 80 90)" "${ram}% en uso"
# Discos
dsk=""
while read -r fs size used avail pct mnt; do
  free=$((100 - ${pct%\%})); [ "$mnt" = "/" ] && dsk=$free
  add "Disco $mnt" "$(lo $free 20 10)" "${free}% libre (${avail} disponibles)"
done < <(df -hP -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | tail -n +2)
# Firewall
if ufw status 2>/dev/null | grep -q 'Status: active'; then add Firewall OK "UFW activo"
elif nft list ruleset 2>/dev/null | grep -q chain; then add Firewall WARN "UFW inactivo; hay reglas nft/iptables"
else add Firewall RISK "Sin firewall activo"; fi
# AppArmor
if aa-status --enabled 2>/dev/null; then add AppArmor OK "Habilitado"; else add AppArmor RISK "No habilitado"; fi
# Actualizaciones
sim="$(apt-get -s dist-upgrade 2>/dev/null)"; np=$(echo "$sim" | grep -c '^Inst '); ns=$(echo "$sim" | grep '^Inst ' | grep -c -- '-security')
stamp=/var/lib/apt/periodic/update-success-stamp; age=999
[ -f "$stamp" ] && age=$(( ( $(date +%s) - $(stat -c %Y "$stamp") ) / 86400 ))
e=OK; [ "$np" -gt 0 ] && e=WARN; [ "$ns" -gt 0 ] && e=WARN; [ "$age" -gt 7 ] && e=WARN
add "Actualizaciones" "$e" "Pendientes=$np (seguridad=$ns); apt update hace ${age} d"
# Eventos críticos (1 h)
cr=$(journalctl --no-pager -q --since -1h -p 0..2 2>/dev/null | wc -l); er=$(journalctl --no-pager -q --since -1h -p 0..3 2>/dev/null | wc -l)
e=OK; [ "$er" -gt 0 ] && e=WARN; [ "$cr" -gt 0 ] && e=RISK
add "Eventos (1 h)" "$e" "Críticos=$cr Errores(total)=$er"
# Servicios
fl=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
if [ -n "$fl" ]; then add Servicios WARN "Fallidos: $fl"; else add Servicios OK "Sin servicios fallidos"; fi
# Roles
for u in docker containerd nginx apache2 mariadb mysql postgresql bind9 named smbd nfs-server haproxy postfix kubelet; do
  systemctl list-unit-files "$u.service" --no-legend 2>/dev/null | grep -q "^$u.service" || continue
  if systemctl is-active --quiet "$u"; then add "Rol $u" OK active
  elif systemctl is-enabled "$u" 2>/dev/null | grep -q '^enabled'; then add "Rol $u" RISK "habilitado y detenido"; fi
done
# Reinicio pendiente
if [ -f /var/run/reboot-required ]; then add "Reinicio pendiente" WARN "$(sort -u /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')"; else add "Reinicio pendiente" OK "No requiere reinicio"; fi
# Resultado
overall=OK; for c in "${CH[@]}"; do case "${c#*|}" in RISK*) overall=RISK;; WARN*) [ "$overall" = OK ] && overall=WARN;; esac; done
ts="$(date -Is)"
esc() { sed 's/\\/\\\\/g; s/"/\\"/g'; }
{
  printf '{"fecha":"%s","servidor":"%s","estado":"%s","checks":[' "$ts" "$(hostname)" "$overall"
  first=1; for c in "${CH[@]}"; do n="${c%%|*}"; r="${c#*|}"; s="${r%%|*}"; d="${r#*|}"
    [ $first -eq 0 ] && printf ','; first=0
    printf '{"check":"%s","estado":"%s","detalle":"%s"}' "$(printf '%s' "$n" | esc)" "$s" "$(printf '%s' "$d" | esc)"
  done; printf ']}\n'
} > "$D/health_latest.json"
printf '%s\n' "${CH[@]}" > "$D/health_latest.txt"
[ -f "$D/health_history.csv" ] || echo "fecha,estado,cpu,ram,disco_raiz_libre_pct" > "$D/health_history.csv"
echo "$ts,$overall,$cpu,$ram,$dsk" >> "$D/health_history.csv"
[ "$(wc -l < "$D/health_history.csv")" -gt 5000 ] && { tail -n 4000 "$D/health_history.csv" > "$D/h.tmp"; (head -1 "$D/health_history.csv"; cat "$D/h.tmp") > "$D/health_history.csv"; rm -f "$D/h.tmp"; }
case "$overall" in OK) exit 0;; WARN) exit 1;; *) exit 2;; esac
HCEOF
  chmod 750 "$HC_SCRIPT"; evfile HealthCheck_script "$HC_SCRIPT" "Creación de $HC_SCRIPT"
  cat > /etc/systemd/system/patchmgmt-health.service <<EOF
[Unit]
Description=Patch Management - Health Check
[Service]
Type=oneshot
ExecStart=$HC_SCRIPT
SuccessExitStatus=1 2
EOF
  cat > /etc/systemd/system/patchmgmt-health.timer <<'EOF'
[Unit]
Description=Patch Management - Health Check cada 5 minutos
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=10s
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  if systemctl enable --now patchmgmt-health.timer >/dev/null 2>&1; then finding F11 OK "Temporizador patchmgmt-health.timer" "Activo, cada 5 min"; else finding F11 RISK "Temporizador patchmgmt-health.timer" "No se pudo habilitar"; fi
  ev timer_info 'systemctl list-timers patchmgmt-health.timer --no-pager; systemctl cat patchmgmt-health.timer'
  "$HC_SCRIPT"; local rc=$?
  if [ -f /var/log/patchmgmt/health_latest.txt ]; then
    evfile health_latest /var/log/patchmgmt/health_latest.json "patchmgmt-healthcheck.sh (ejecución inmediata)"
    local ov; case $rc in 0) ov=OK;; 1) ov=WARN;; *) ov=RISK;; esac
    finding F11 "$ov" "Health Check (ejecución inmediata)" "Estado global: $ov (exit $rc)"
    while IFS='|' read -r n s d; do finding F11 "$s" "$n" "$d"; done < /var/log/patchmgmt/health_latest.txt
  else finding F11 RISK "Health Check (ejecución inmediata)" "No generó health_latest"; fi
  sec F11 EstadoInicial "Sin Health Check previo."
  sec F11 Accion "Creación de $HC_SCRIPT y de patchmgmt-health.timer (cada 5 min, systemd). Ejecución inmediata."
  sec F11 Resultado "Salida continua en /var/log/patchmgmt (health_latest.json, health_history.csv)."
  sec F11 Validacion "El script se ejecutó una vez y se leyó su resultado."
  sec F11 Rollback "${BT}systemctl disable --now patchmgmt-health.timer; rm /etc/systemd/system/patchmgmt-health.{service,timer} $HC_SCRIPT; systemctl daemon-reload${BT}"
  sec F11 Recomendaciones "Si hay monitoreo central, recolectar /var/log/patchmgmt/health_latest.json."
}

# =============================================================================
# FASE 12 - INFORMES (MD / HTML / PDF)
# =============================================================================
write_tools() {
cat > "$BASE/.report_tools.py" <<'PYEOF'
import sys, re, html

def inline(t):
    t = html.escape(t)
    t = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', t)
    return re.sub(r'`(.+?)`', r'<code>\1</code>', t)

def md2html(md, title):
    out = []; st = {'code': False, 'tbl': False, 'ul': False, 'first': True}
    def close():
        if st['ul']: out.append('</ul>'); st['ul'] = False
        if st['tbl']: out.append('</table>'); st['tbl'] = False
    for l in md.splitlines():
        if l.startswith('```'):
            if st['code']: out.append('</pre>'); st['code'] = False
            else: close(); out.append('<pre>'); st['code'] = True
            continue
        if st['code']: out.append(html.escape(l)); continue
        if l.startswith('|'):
            if re.match(r'^\|[\s\-:|]+\|?\s*$', l): continue
            if not st['tbl']: close(); out.append('<table>'); st['tbl'] = True; st['first'] = True
            tag = 'th' if st['first'] else 'td'; st['first'] = False
            cells = [inline(c.strip()) for c in l.strip().strip('|').split('|')]
            out.append('<tr>' + ''.join('<%s>%s</%s>' % (tag, c, tag) for c in cells) + '</tr>'); continue
        m = re.match(r'^- (.*)', l)
        if m:
            if st['tbl']: out.append('</table>'); st['tbl'] = False
            if not st['ul']: out.append('<ul>'); st['ul'] = True
            out.append('<li>' + inline(m.group(1)) + '</li>'); continue
        close()
        m = re.match(r'^(#{1,4}) (.*)', l)
        if m: n = len(m.group(1)); out.append('<h%d>%s</h%d>' % (n, inline(m.group(2)), n)); continue
        if l.strip(): out.append('<p>' + inline(l) + '</p>')
    close()
    css = 'body{font-family:Segoe UI,Arial,sans-serif;margin:30px;color:#222;max-width:1100px}h1{border-bottom:3px solid #0b5394}h2{color:#0b5394;margin-top:28px}h3{color:#444}table{border-collapse:collapse;margin:8px 0}th,td{border:1px solid #bbb;padding:4px 8px;font-size:13px}th{background:#e8eef7}code{background:#f2f2f2;padding:1px 4px;font-size:12px}pre{background:#f6f6f6;padding:8px;overflow:auto}li{margin:2px 0}'
    return '<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>%s</title><style>%s</style></head><body>%s</body></html>' % (html.escape(title), css, '\n'.join(out))

def simple_pdf(text, path):
    for a, b in (('🟢', '[OK]'), ('🟡', '[ADVERTENCIA]'), ('🔴', '[RIESGO]'), ('ℹ️', '[i]'), ('**', ''), ('`', ''), ('•', '-')):
        text = text.replace(a, b)
    text = ''.join(c if (c in '\t\n\r' or 32 <= ord(c) <= 255) else '?' for c in text)
    W, PER = 100, 64; lines = []
    for ln in text.replace('\t', '  ').splitlines():
        if len(ln) <= W: lines.append(ln)
        else: lines += [ln[i:i+W] for i in range(0, len(ln), W)]
    pages = max(1, -(-len(lines) // PER)); buf = bytearray(); offs = {}
    def w(s): buf.extend(s.encode('latin-1'))
    w('%PDF-1.4\n')
    kids = ' '.join('%d 0 R' % (5 + 2*i) for i in range(pages))
    offs[1] = len(buf); w('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n')
    offs[2] = len(buf); w('2 0 obj\n<< /Type /Pages /Kids [%s] /Count %d >>\nendobj\n' % (kids, pages))
    offs[3] = len(buf); w('3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\nendobj\n')
    for p in range(pages):
        cid, pid = 4 + 2*p, 5 + 2*p
        body = 'BT /F1 8 Tf 10 TL 40 755 Td\n' + ''.join('(%s) Tj T*\n' % l.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)') for l in lines[p*PER:(p+1)*PER]) + 'ET'
        offs[cid] = len(buf); w('%d 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n' % (cid, len(body), body))
        offs[pid] = len(buf); w('%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources << /Font << /F1 3 0 R >> >> >>\nendobj\n' % (pid, cid))
    n = 4 + 2*pages; x = len(buf)
    w('xref\n0 %d\n0000000000 65535 f \n' % n)
    for i in range(1, n): w('%010d 00000 n \n' % offs[i])
    w('trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF' % (n, x))
    open(path, 'wb').write(buf)

if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'html':
        open(sys.argv[3], 'w', encoding='utf-8').write(md2html(open(sys.argv[2], encoding='utf-8').read(), sys.argv[4]))
    elif mode == 'pdf':
        simple_pdf(open(sys.argv[2], encoding='utf-8').read(), sys.argv[3])
PYEOF
}

fase12() {
  CUR=F12; hdr "FASE 12 - INFORMES"
  write_report Inventario.md 'Inventario' F1
  write_report PreCheck.md 'Pre-Check y Respaldos' F2 F3
  write_report Actualizaciones.md 'Actualizaciones, Instalación y Reinicio' F4 F5 F6
  write_report Hardening.md 'Hardening posterior' F8
  write_report Eventos.md 'Logs del sistema (journald)' F9
  write_report Validacion.md 'Validación posterior y operativa' F7 F10
  write_report HealthCheck.md 'Health Check' F11

  local all="F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11" nok nw nr w end dur ni nf pa inst
  nok=$(awk -F'\t' '$2=="OK"' "$FIND" | wc -l); nw=$(awk -F'\t' '$2=="WARN"' "$FIND" | wc -l); nr=$(awk -F'\t' '$2=="RISK"' "$FIND" | wc -l)
  w="$(worst $all)"; end=$(date +%s); dur=$((end - $(mget start_epoch)))
  ni=$(wc -l < "$META/installed_list" 2>/dev/null); nf=$(wc -l < "$META/failed_list" 2>/dev/null); pa="$(mget pending_after)"
  {
    report_header 'Informe Final - Patch Management Ubuntu Server 26.04' $all
    cat <<EOF
## Resumen ejecutivo

| Concepto | Valor |
|---|---|
| Servidor | $(hostname) ($SERVER_IP) |
| Sistema operativo | $(. /etc/os-release; echo "$PRETTY_NAME") - kernel $(uname -r) |
| Inicio / Fin | $(mget start) / $(date '+%F %T') |
| Duración total (incluye reinicio) | $(fmt_dur $dur) |
| Actualizaciones pendientes detectadas | $(mget pending_count) (seguridad: $(mget pending_sec)) |
| Paquetes actualizados | ${ni:-0} |
| Errores de instalación | ${nf:-0} (apt-get exit: $(mget install_rc || echo n/a)) |
| Reinicio requerido | $([ "$(mget reboot_needed)" = 1 ] && echo "Sí - $(mget reboot_reason) - indisponibilidad: $(mget downtime)" || echo "No") |
| Pendientes tras el parcheo | ${pa:-n/d} |
| Hallazgos | 🟢 Correcto: $nok / 🟡 Advertencia: $nw / 🔴 Riesgo: $nr |
| Estado global | $(ico "$w") $w |

### Paquetes actualizados

$(if [ "${ni:-0}" -gt 0 ]; then sed 's/^/- /' "$META/installed_list" | head -100; else echo "- Ninguno en esta corrida."; fi)

### Hallazgos con Advertencia / Riesgo

$(awk -F'\t' '$2=="WARN"||$2=="RISK"{print "- ["$2"] ["$1"] **"$3"**: "$4}' "$FIND" | sed 's/^- \[WARN\]/- 🟡/; s/^- \[RISK\]/- 🔴/')

# Detalle por fase

EOF
    local p; for p in F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11; do phase_md "$p" '##'; echo; done
  } > "$BASE/Informe_Final.md"
  write_tools
  python3 "$BASE/.report_tools.py" html "$BASE/Informe_Final.md" "$BASE/Informe_Final.html" "Informe Final - Patch Management" || echo "  (fallo al generar HTML)"
  rm -f "$BASE/Informe_Final.pdf"
  if command -v wkhtmltopdf >/dev/null; then wkhtmltopdf -q "$BASE/Informe_Final.html" "$BASE/Informe_Final.pdf" 2>/dev/null
  elif command -v weasyprint >/dev/null; then weasyprint -q "$BASE/Informe_Final.html" "$BASE/Informe_Final.pdf" 2>/dev/null
  elif command -v pandoc >/dev/null && command -v pdflatex >/dev/null; then pandoc "$BASE/Informe_Final.md" -o "$BASE/Informe_Final.pdf" 2>/dev/null; fi
  if [ ! -s "$BASE/Informe_Final.pdf" ]; then
    python3 "$BASE/.report_tools.py" pdf "$BASE/Informe_Final.md" "$BASE/Informe_Final.pdf" && echo "  PDF generado con el generador interno (texto plano, Courier)."
  fi
  ( cd "$BASE" && sha256sum *.md *.html *.pdf > "$EV/SHA256SUMS_informes.txt" 2>/dev/null )
  ( cd "$EV" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS_evidencias.txt' -print0 | xargs -0 sha256sum > SHA256SUMS_evidencias.txt 2>/dev/null )
  mset stage "done"
}

show_final() {
  local ok="✔" no="✘" f c w m docs=1 x
  L() { w="$(worst "${@:2}")"; m=$ok; [ "$w" = RISK ] && m=$no; case $w in OK) c=32;; WARN) c=33;; *) c=31;; esac; printf '  \033[%sm%s %s  %s\033[0m\n' "$c" "$m" "$1" "$(ico "$w")"; }
  for x in Inventario.md PreCheck.md Actualizaciones.md Hardening.md Eventos.md Validacion.md HealthCheck.md Informe_Final.md Informe_Final.html Informe_Final.pdf; do [ -s "$BASE/$x" ] || docs=0; done
  echo; echo "=========================================================="; echo
  echo "   PATCH MANAGEMENT"; echo "   UBUNTU SERVER 26.04 LTS"; echo
  echo "   Administrador: $RESPONSABLE"; echo "   Servidor: $SERVER_IP ($(hostname))"; echo
  L "Inventario Inicial" F1; L "Pre-Check" F2; L "Backups" F3; L "Actualizaciones (APT)" F4; L "Instalación de paquetes" F5
  L "Reinicio Validado" F6; L "Hardening" F8; L "Logs del sistema" F9; L "Health Check" F11; L "Validación Operativa" F7 F10
  [ $docs -eq 1 ] && printf '  \033[32m%s Documentación\033[0m\n' "$ok" || printf '  \033[31m%s Documentación\033[0m\n' "$no"
  echo; echo "=========================================================="; echo; echo "  ESTADO FINAL"; echo
  local upd=0 val=0 hard=0 nocrit=0
  [ "$(mget install_exec)" = "1" ] && [ "$(mget install_rc)" = "0" ] && [ ! -s "$META/failed_list" ] && [ "$(mget pending_after)" = "0" ] && upd=1
  [ "$(worst F6 F7 F10)" != RISK ] && val=1; [ "$(worst F8)" != RISK ] && hard=1; [ "$(worst F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11)" != RISK ] && nocrit=1
  [ $upd -eq 1 ] && printf '  \033[32mSERVIDOR ACTUALIZADO\033[0m\n' || printf '  \033[33mACTUALIZACIÓN INCOMPLETA (omitida/fallidas/pendientes) - ver informe\033[0m\n'
  [ $val -eq 1 ] && printf '  \033[32mSERVIDOR VALIDADO\033[0m\n' || printf '  \033[31mVALIDACIÓN CON RIESGOS\033[0m\n'
  [ $hard -eq 1 ] && printf '  \033[32mSERVIDOR ENDURECIDO (sin riesgos en verificación)\033[0m\n' || printf '  \033[31mHARDENING CON RIESGOS PENDIENTES\033[0m\n'
  [ $nocrit -eq 1 ] && printf '  \033[32mSIN ERRORES CRÍTICOS\033[0m\n' || printf '  \033[31mEXISTEN HALLAZGOS DE RIESGO\033[0m\n'
  [ $docs -eq 1 ] && printf '  \033[32mDOCUMENTACIÓN COMPLETA\033[0m\n' || printf '  \033[31mDOCUMENTACIÓN INCOMPLETA\033[0m\n'
  echo; echo "  Informes:   $BASE"; echo "  Evidencias: $EV"; echo "  Respaldos:  $(mget backup_dir)"; echo
  printf '  \033[36mMarcelo Gallardo - Autor • Investigador • Ingeniero en Sistemas\n  https://panivinux.base44.app/\033[0m\n\n'
  echo "=========================================================="
}

# =============================================================================
# FLUJO PRINCIPAL
# =============================================================================
main() {
  if [ "$CONTINUE" -eq 0 ]; then
    fase1; fase2; fase3; fase4; fase5
    if fase6_prepare; then
      if [ "$AUTO_REBOOT" -eq 1 ]; then
        local args=(--continue --responsable "$RESPONSABLE" --min-free-gb "$MIN_FREE_GB" --event-days "$EVENT_DAYS")
        [ -n "$EXPECTED_IP" ] && args+=(--expected-ip "$EXPECTED_IP"); [ "$APPLY_HARD" -eq 1 ] && args+=(--apply-hardening); [ "$FORCE" -eq 1 ] && args+=(--force)
        cat > /etc/systemd/system/patchmgmt-continue.service <<EOF
[Unit]
Description=Patch Management - continuación tras reinicio
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
TimeoutStartSec=0
ExecStart=$(printf '%q ' "$SCRIPT_PATH" "${args[@]}")
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload; systemctl enable patchmgmt-continue.service >/dev/null 2>&1
        echo; echo "  Reinicio en 1 minuto. La corrida continuará automáticamente (patchmgmt-continue.service). Cancelar: shutdown -c"
        shutdown -r +1 "Patch Management: reinicio controlado"
        exit 0
      else
        echo; echo "  REINICIO PENDIENTE. Reinicie el servidor y luego ejecute:  sudo $SCRIPT_PATH --continue"
        exit 0
      fi
    fi
  fi
  fase6_validate; fase7; fase8; fase9; fase10; fase11; fase12; show_final
}
main
