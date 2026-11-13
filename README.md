Patch Management para Windows Server 2025 y Ubuntu Server 26.04

Scripts de parcheo controlado para el curso Hardening de Servidores Windows y Linux (Escuela Politécnica Nacional).

Cada script ejecuta el proceso completo: inventario, pre-check, respaldos (con SHA256), instalación de actualizaciones, reinicio controlado, validación posterior, verificación de hardening, análisis de logs, Health Check cada 5 minutos e informes en Markdown, HTML y PDF. Funcionan en cualquier servidor, con cualquier IP: la IP se detecta sola.

Archivo	Sistema	Se ejecuta con
Invoke-PatchManagement.ps1	Windows Server 2025	PowerShell como Administrador
patch-management-ubuntu.sh	Ubuntu Server 26.04 LTS	sudo (root)

Antes de empezar: úselos solo en servidores donde tenga autorización. Tome un snapshot de la VM y verifique que el servidor tenga acceso a Internet (Microsoft Update y PowerShell Gallery en Windows; repositorios de Ubuntu en Linux).

Windows Server 2025
1. Preparar

Copie el script al servidor (por ejemplo a C:\Temp), abra PowerShell como Administrador y ejecute:

powershell
cd C:\Temp
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Unblock-File .\Invoke-PatchManagement.ps1
2. Ejecutar
powershell
# Prueba segura: NO instala nada (recomendada como primera ejecución)
.\Invoke-PatchManagement.ps1 -SkipInstall

# Ejecución completa, con reinicio automático (continúa sola al arrancar)
.\Invoke-PatchManagement.ps1 -AutoReboot

# Ejecución completa, con reinicio manual
.\Invoke-PatchManagement.ps1
#   ...si queda un reinicio pendiente, el script se detiene: reinicie el servidor y luego:
.\Invoke-PatchManagement.ps1 -Continue
3. Parámetros
Parámetro	Descripción	Por defecto
-SkipInstall	No instala actualizaciones (inventario, pre-check, respaldos, escaneo y validaciones).	—
-AutoReboot	Si hay reinicio pendiente, reinicia y continúa solo (tarea PatchMgmt-Continue).	—
-Continue	Continúa una ejecución que quedó pendiente de reinicio.	—
-ApplyHardening	Deshabilita SMBv1 si estuviera activo (nunca lo habilita).	—
-ExpectedIP <IP>	Opcional: el script se detiene si el servidor no tiene esa IP.	vacío (no valida)
-Force	Con -ExpectedIP, continúa aunque la IP no coincida.	—
-Responsable "<Nombre>"	Nombre que aparece en los informes.	Marcelo Gallardo
-MinFreeGB <n>	Espacio libre mínimo en la unidad del sistema.	20
-EventDays <n>	Días de eventos a analizar.	7
-BaseDir <ruta>	Carpeta de informes y evidencias.	C:\PatchManagement
-BackupDir <ruta>	Carpeta de respaldos.	C:\PatchBackup
-ScriptsDir <ruta>	Carpeta donde se crea HealthCheck.ps1.	C:\Scripts
4. Resultados
Ruta	Contenido
C:\PatchManagement\Informe_Final.pdf (.html, .md)	Informe final
C:\PatchManagement\*.md	Informes por tema: Inventario, PreCheck, WindowsUpdate, Hardening, Eventos, Validacion, HealthCheck
C:\PatchManagement\Evidencias\	Salida de todos los comandos ejecutados
C:\PatchBackup\	Respaldos con hash SHA256
C:\Scripts\HealthCheck.ps1	Health Check (tarea HealthCheck-5min, cada 5 minutos)
Ubuntu Server 26.04 LTS
1. Preparar

Copie el script al servidor (WinSCP o scp). Si el archivo viene de Windows, elimine los saltos de línea de Windows y dé permiso de ejecución:

bash
sed -i 's/\r$//' patch-management-ubuntu.sh
chmod +x patch-management-ubuntu.sh
2. Ejecutar
bash
# Prueba segura: NO instala nada (recomendada como primera ejecución)
sudo ./patch-management-ubuntu.sh --skip-install

# Ejecución completa, con reinicio automático (continúa sola al arrancar)
sudo ./patch-management-ubuntu.sh --auto-reboot

# Ejecución completa, con reinicio manual
sudo ./patch-management-ubuntu.sh
#   ...si queda un reinicio pendiente, el script se detiene: reinicie el servidor y luego:
sudo ./patch-management-ubuntu.sh --continue
3. Parámetros
Parámetro	Descripción	Por defecto
--skip-install	No instala actualizaciones (inventario, pre-check, respaldos, escaneo y validaciones).	—
--auto-reboot	Si hay reinicio pendiente, reinicia en 1 minuto y continúa solo (servicio patchmgmt-continue).	—
--continue	Continúa una ejecución que quedó pendiente de reinicio.	—
--apply-hardening	Crea un archivo sysctl de hardening, reversible. No toca SSH ni UFW.	—
--allow-removals	Permite instalar aunque full-upgrade vaya a eliminar paquetes (sin esto, el script no instala y lo reporta).	—
--include-snap	Ejecuta también snap refresh.	—
--expected-ip <IP>	Opcional: el script se detiene si el servidor no tiene esa IP.	vacío (no valida)
--force	Con --expected-ip, continúa aunque la IP no coincida.	—
--responsable "<Nombre>"	Nombre que aparece en los informes.	Marcelo Gallardo
--min-free-gb <n>	Espacio libre mínimo en /.	10
--event-days <n>	Días de logs (journald) a analizar.	7
4. Resultados
Ruta	Contenido
/opt/PatchManagement/Informe_Final.pdf (.html, .md)	Informe final
/opt/PatchManagement/*.md	Informes por tema: Inventario, PreCheck, Actualizaciones, Hardening, Eventos, Validacion, HealthCheck
/opt/PatchManagement/Evidencias/	Salida de todos los comandos ejecutados
/var/backups/PatchBackup/	Respaldos con hash SHA256
/usr/local/sbin/patchmgmt-healthcheck.sh	Health Check (temporizador patchmgmt-health.timer, cada 5 minutos)
/var/log/patchmgmt/	Resultados del Health Check
Cómo leer el resultado

Al terminar, ambos scripts muestran un resumen por fase y un ESTADO FINAL. Cada hallazgo se clasifica así:

Icono	Significado
🟢 Correcto	Sin observaciones.
🟡 Advertencia	Revisar; no es crítico.
🔴 Riesgo	Requiere atención antes de dar el servidor por validado.

Los textos "SERVIDOR ACTUALIZADO / VALIDADO / ENDURECIDO" solo aparecen si la evidencia lo respalda. Revise siempre el Informe_Final antes de cerrar la tarea.

Estado de las pruebas
patch-management-ubuntu.sh: analizado con ShellCheck y ejecutado completo en Ubuntu 24.04 (modo --skip-install). No se probaron en Ubuntu 26.04 los componentes de systemd (temporizador, servicio de continuación), la instalación real de paquetes ni un reinicio real.
Invoke-PatchManagement.ps1: sintaxis validada con el parser de PowerShell y generación de informes probada. Los comandos propios de Windows (Windows Update, Firewall, Defender, eventos, tareas programadas) no se han ejecutado en un Windows Server real.

Se recomienda empezar siempre con -SkipInstall / --skip-install.

Marcelo Iván Gallardo Nicolalde (PaniVinux) Autor • Investigador • Ingeniero en Sistemas https://panivinux.base44.app/
