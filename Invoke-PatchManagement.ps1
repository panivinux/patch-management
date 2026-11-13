#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
  Patch Management empresarial - Windows Server 2025 (cualquier servidor)
.NOTES
  Marcelo Gallardo - Autor • Investigador • Ingeniero en Sistemas
  https://panivinux.base44.app/
.DESCRIPTION
  Fases 1-12: inventario, pre-check, respaldos (SHA256), Windows Update (PSWindowsUpdate / PSGallery),
  instalación única, reinicio controlado, validación, hardening (verificación), Event Viewer,
  validación operativa, Health Check (cada 5 min) e informes MD/HTML/PDF.
  Toda la información sale del servidor. No inventa resultados.

.EXAMPLES
  .\Invoke-PatchManagement.ps1                      # Ejecuta hasta la fase 6; si hay reinicio pendiente se detiene
  .\Invoke-PatchManagement.ps1 -AutoReboot          # Reinicia solo y continúa (tarea de inicio) con fases 6-12
  .\Invoke-PatchManagement.ps1 -Continue            # Continúa tras un reinicio manual
  .\Invoke-PatchManagement.ps1 -SkipInstall         # Solo inventario/pre-check/respaldos/escaneo/validaciones
  .\Invoke-PatchManagement.ps1 -ApplyHardening      # Además desactiva SMBv1 si estuviera activo (nunca lo habilita)
#>
[CmdletBinding()]
param(
    [string]$ExpectedIP  = '',   # opcional: si se indica, el script verifica que esté en el servidor correcto
    [string]$Responsable = 'Marcelo Gallardo',
    [int]$MinFreeGB      = 20,
    [int]$EventDays      = 7,
    [string]$BaseDir     = 'C:\PatchManagement',
    [string]$BackupDir   = 'C:\PatchBackup',
    [string]$ScriptsDir  = 'C:\Scripts',
    [switch]$SkipInstall,
    [switch]$AutoReboot,
    [switch]$ApplyHardening,
    [switch]$Continue,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$ScriptPath = $MyInvocation.MyCommand.Path

# IP principal detectada automáticamente (el script funciona en cualquier servidor)
function Get-PrimaryIP {
    try {
        $cfg = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
        if ($cfg -and $cfg.IPv4Address) { return @($cfg.IPv4Address)[0].IPAddress }
        $a = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
        if ($a) { return $a.IPAddress }
    } catch {}
    return 'n/d'
}
$ServerIP = Get-PrimaryIP
$BT = [char]96

# ---------------------------------------------------------------- Iconos
$IcoOK   = [char]::ConvertFromUtf32(0x1F7E2)
$IcoWARN = [char]::ConvertFromUtf32(0x1F7E1)
$IcoRISK = [char]::ConvertFromUtf32(0x1F534)
function Ico($e) { switch ($e) { 'OK' { $IcoOK } 'WARN' { $IcoWARN } 'RISK' { $IcoRISK } default { '[i]' } } }

# ---------------------------------------------------------------- Inicialización de corrida
New-Item -ItemType Directory -Force -Path $BaseDir, $BackupDir, $ScriptsDir | Out-Null
$CurPtr = Join-Path $BaseDir 'current_run.txt'

if ($Continue) {
    if (-not (Test-Path $CurPtr)) { throw 'No existe corrida previa (current_run.txt). Ejecute primero sin -Continue.' }
    $RunId     = (Get-Content $CurPtr -Raw).Trim()
    $RunDir    = Join-Path $BaseDir "Run_$RunId"
    $StatePath = Join-Path $RunDir 'state.clixml'
    $St = Import-Clixml $StatePath
} else {
    $RunId     = Get-Date -Format 'yyyyMMdd_HHmmss'
    $RunDir    = Join-Path $BaseDir "Run_$RunId"
    $StatePath = Join-Path $RunDir 'state.clixml'
    New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
    Set-Content -Path $CurPtr -Value $RunId -Encoding ASCII
    $St = @{ RunId = $RunId; Start = Get-Date; Findings = @(); Evid = @(); Sec = @{}; Meta = @{}; Stage = 'start' }
}
$EvDir = Join-Path $BaseDir "Evidencias\$RunId"
New-Item -ItemType Directory -Force -Path $EvDir | Out-Null
Start-Transcript -Path (Join-Path $RunDir 'transcript.log') -Append | Out-Null

$script:CurPhase = ''

$PhaseTitle = [ordered]@{
    F1 = 'Fase 1 - Inventario inicial'; F2 = 'Fase 2 - Pre-check de parcheo'; F3 = 'Fase 3 - Respaldos'
    F4 = 'Fase 4 - Windows Update'; F5 = 'Fase 5 - Instalación controlada'; F6 = 'Fase 6 - Reinicio controlado'
    F7 = 'Fase 7 - Validación posterior'; F8 = 'Fase 8 - Hardening posterior'; F9 = 'Fase 9 - Event Viewer'
    F10 = 'Fase 10 - Validación operativa'; F11 = 'Fase 11 - Health Check'
}
$SecKeys = [ordered]@{
    EstadoInicial = 'Estado inicial'; Evidencia = 'Evidencia'; Diagnostico = 'Diagnóstico'
    Accion = 'Acción ejecutada'; Resultado = 'Resultado'; Validacion = 'Validación'
    Rollback = 'Rollback'; Recomendaciones = 'Recomendaciones'; Conclusion = 'Conclusión'
}

# ---------------------------------------------------------------- Helpers
function Save-State { $St | Export-Clixml -Path $StatePath -Depth 8 }

function Add-Finding {
    param([string]$Fase, [string]$Item, [ValidateSet('OK', 'WARN', 'RISK', 'INFO')][string]$Estado, [string]$Detalle = '')
    $St.Findings += [pscustomobject]@{ Fase = $Fase; Item = $Item; Estado = $Estado; Detalle = $Detalle }
    $c = @{ OK = 'Green'; WARN = 'Yellow'; RISK = 'Red'; INFO = 'Cyan' }[$Estado]
    Write-Host ('  [{0}] {1} - {2}' -f $Estado, $Item, $Detalle) -ForegroundColor $c
}

function Get-Worst($f) {
    $f = @($f)
    if ($f | Where-Object { $_.Estado -eq 'RISK' }) { return 'RISK' }
    if ($f | Where-Object { $_.Estado -eq 'WARN' }) { return 'WARN' }
    return 'OK'
}

function Set-Sec {
    param([string]$Fase, [hashtable]$Data)
    if (-not $St.Sec.ContainsKey($Fase)) { $St.Sec[$Fase] = @{} }
    foreach ($k in $Data.Keys) { $St.Sec[$Fase][$k] = $Data[$k] }
}

function Save-Text {
    param([string]$Name, [string]$Text, [string]$Cmd)
    $f = Join-Path $EvDir "$($script:CurPhase)_$Name.txt"
    "# Comando: $Cmd`r`n# Fecha: $(Get-Date -Format o)`r`n$Text" | Set-Content -Path $f -Encoding UTF8
    $St.Evid += [pscustomobject]@{ Fase = $script:CurPhase; Nombre = $Name; Comando = $Cmd; Archivo = $f }
}

function Save-Ev {
    param([string]$Name, [scriptblock]$Block)
    $cmd = ($Block.ToString().Trim() -replace '\s*\r?\n\s*', ' ; ')
    try { $o = (& $Block 2>&1 | Out-String -Width 250).TrimEnd() } catch { $o = 'ERROR: ' + $_.Exception.Message }
    Save-Text $Name $o $cmd
    return $o
}

function Add-EvFile {
    param([string]$Name, [string]$Path, [string]$Cmd)
    $St.Evid += [pscustomobject]@{ Fase = $script:CurPhase; Nombre = $Name; Comando = $Cmd; Archivo = $Path }
}

function Get-PendingReboot {
    $r = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $r += 'CBS RebootPending' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $r += 'WindowsUpdate RebootRequired' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress') { $r += 'CBS RebootInProgress' }
    $p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($p) { $r += 'PendingFileRenameOperations' }
    return $r
}

function Fmt-Hr($ex) { if ($ex -and $ex.HResult) { '0x{0:X8}' -f $ex.HResult } else { 'n/d' } }

# ---------------------------------------------------------------- Informes (MD / HTML / PDF)
function Get-PhaseMd {
    param([string]$ph, [string]$lvl = '##')
    $f = @($St.Findings | Where-Object { $_.Fase -eq $ph })
    $w = Get-Worst $f
    $s = $St.Sec[$ph]
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("$lvl $($PhaseTitle[$ph]) $(Ico $w)")
    [void]$sb.AppendLine('')
    foreach ($k in $SecKeys.Keys) {
        [void]$sb.AppendLine("$lvl# $($SecKeys[$k])")
        [void]$sb.AppendLine('')
        switch ($k) {
            'Evidencia' {
                $ev = @($St.Evid | Where-Object { $_.Fase -eq $ph })
                if ($ev.Count -eq 0) { [void]$sb.AppendLine('- Sin evidencias generadas en esta fase.') }
                foreach ($e in $ev) { [void]$sb.AppendLine("- Comando: $BT$($e.Comando)$BT -> Evidencia: $BT$($e.Archivo)$BT") }
            }
            'Diagnostico' {
                if ($f.Count -eq 0) { [void]$sb.AppendLine('- Sin hallazgos registrados.') }
                foreach ($x in $f) { [void]$sb.AppendLine("- $(Ico $x.Estado) **$($x.Item)**: $($x.Detalle)") }
            }
            'Conclusion' {
                $txt = if ($s -and $s['Conclusion']) { $s['Conclusion'] } else { '' }
                [void]$sb.AppendLine("Estado de la fase: $(Ico $w) $w. $txt")
            }
            default {
                $txt = if ($s -and $s[$k]) { $s[$k] } else { 'No registrado.' }
                [void]$sb.AppendLine($txt)
            }
        }
        [void]$sb.AppendLine('')
    }
    return $sb.ToString()
}

function Get-ReportHeader {
    param([string]$Title, [string[]]$Phases)
    $f = @($St.Findings | Where-Object { $Phases -contains $_.Fase })
    $w = Get-Worst $f
    $now = Get-Date
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    return @"
# $Title

- **Fecha:** $($now.ToString('yyyy-MM-dd'))
- **Hora:** $($now.ToString('HH:mm:ss'))
- **Servidor:** $env:COMPUTERNAME ($ServerIP) - $os
- **Responsable:** $Responsable
- **Corrida:** $RunId
- **Estado:** $(Ico $w) $w
- **Autor del script:** Marcelo Gallardo - Autor • Investigador • Ingeniero en Sistemas - https://panivinux.base44.app/

"@
}

function Write-PhaseReport {
    param([string]$File, [string]$Title, [string[]]$Phases)
    $md = Get-ReportHeader $Title $Phases
    foreach ($p in $Phases) { $md += (Get-PhaseMd $p '##') + "`r`n" }
    Set-Content -Path (Join-Path $BaseDir $File) -Value $md -Encoding UTF8
}

function ConvertTo-HtmlDoc {
    param([string]$Md, [string]$Title)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode($s) }
    $sb = New-Object System.Text.StringBuilder
    $inCode = $false; $inTbl = $false; $inUl = $false; $first = $true
    $close = { if ($inUl) { [void]$sb.AppendLine('</ul>'); $inUl = $false }; if ($inTbl) { [void]$sb.AppendLine('</table>'); $inTbl = $false } }
    $inline = { param($t) $t = & $enc $t; $t = $t -replace '\*\*(.+?)\*\*', '<strong>$1</strong>'; $t -replace ([regex]::Escape($BT) + '(.+?)' + [regex]::Escape($BT)), '<code>$1</code>' }
    foreach ($l in ($Md -split "`r?`n")) {
        if ($l -match '^```') {
            if ($inCode) { [void]$sb.AppendLine('</pre>'); $inCode = $false } else { . $close; [void]$sb.AppendLine('<pre>'); $inCode = $true }
            continue
        }
        if ($inCode) { [void]$sb.AppendLine((& $enc $l)); continue }
        if ($l -match '^\|') {
            if ($l -match '^\|[\s\-:|]+\|?\s*$') { continue }
            if (-not $inTbl) { . $close; [void]$sb.AppendLine('<table>'); $inTbl = $true; $first = $true }
            $cells = ($l.Trim().Trim('|') -split '\|') | ForEach-Object { & $inline $_.Trim() }
            $tag = if ($first) { 'th' } else { 'td' }; $first = $false
            [void]$sb.AppendLine('<tr>' + (($cells | ForEach-Object { "<$tag>$_</$tag>" }) -join '') + '</tr>')
            continue
        }
        if ($l -match '^- (.*)') {
            if ($inTbl) { [void]$sb.AppendLine('</table>'); $inTbl = $false }
            if (-not $inUl) { [void]$sb.AppendLine('<ul>'); $inUl = $true }
            [void]$sb.AppendLine('<li>' + (& $inline $Matches[1]) + '</li>'); continue
        }
        . $close
        if ($l -match '^(#{1,4}) (.*)') { $n = $Matches[1].Length; [void]$sb.AppendLine("<h$n>" + (& $inline $Matches[2]) + "</h$n>"); continue }
        if ($l.Trim() -ne '') { [void]$sb.AppendLine('<p>' + (& $inline $l) + '</p>') }
    }
    . $close
    $css = 'body{font-family:Segoe UI,Arial,sans-serif;margin:30px;color:#222;max-width:1100px}h1{border-bottom:3px solid #0b5394}h2{color:#0b5394;margin-top:28px}h3{color:#444}table{border-collapse:collapse;margin:8px 0}th,td{border:1px solid #bbb;padding:4px 8px;font-size:13px}th{background:#e8eef7}code{background:#f2f2f2;padding:1px 4px;font-size:12px}pre{background:#f6f6f6;padding:8px;overflow:auto}li{margin:2px 0}'
    return "<!DOCTYPE html><html lang=`"es`"><head><meta charset=`"utf-8`"><title>$Title</title><style>$css</style></head><body>$($sb.ToString())</body></html>"
}

function New-SimplePdf {
    param([string]$Text, [string]$Path)
    $enc = [Text.Encoding]::GetEncoding(28591)
    $t = $Text.Replace($IcoOK, '[OK]').Replace($IcoWARN, '[ADVERTENCIA]').Replace($IcoRISK, '[RIESGO]').Replace([string][char]0x2022, '-')
    $t = $t -replace '[^\u0009\u000A\u000D\u0020-\u00FF]', '?'
    $t = $t -replace '\*\*', '' -replace [regex]::Escape($BT), ''
    $w = 100; $per = 64; $lines = New-Object System.Collections.Generic.List[string]
    foreach ($ln in ($t -split "`r?`n")) {
        $ln = $ln -replace "`t", '  '
        if ($ln.Length -le $w) { $lines.Add($ln) } else { for ($i = 0; $i -lt $ln.Length; $i += $w) { $lines.Add($ln.Substring($i, [Math]::Min($w, $ln.Length - $i))) } }
    }
    $pages = [Math]::Max(1, [Math]::Ceiling($lines.Count / $per))
    $ms = New-Object System.IO.MemoryStream; $offs = @{}
    $wr = { param($s) $b = $enc.GetBytes($s); $ms.Write($b, 0, $b.Length) }
    & $wr "%PDF-1.4`n"
    $kids = (0..($pages - 1) | ForEach-Object { '{0} 0 R' -f (5 + 2 * $_) }) -join ' '
    $offs[1] = $ms.Position; & $wr "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n"
    $offs[2] = $ms.Position; & $wr "2 0 obj`n<< /Type /Pages /Kids [$kids] /Count $pages >>`nendobj`n"
    $offs[3] = $ms.Position; & $wr "3 0 obj`n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>`nendobj`n"
    for ($p = 0; $p -lt $pages; $p++) {
        $cid = 4 + 2 * $p; $pid2 = 5 + 2 * $p
        $chunk = $lines | Select-Object -Skip ($p * $per) -First $per
        $cs = New-Object System.Text.StringBuilder
        [void]$cs.Append("BT /F1 8 Tf 10 TL 40 755 Td`n")
        foreach ($c in $chunk) { $e = $c.Replace('\', '\\').Replace('(', '\(').Replace(')', '\)'); [void]$cs.Append("($e) Tj T*`n") }
        [void]$cs.Append('ET')
        $body = $cs.ToString()
        $offs[$cid] = $ms.Position; & $wr "$cid 0 obj`n<< /Length $($body.Length) >>`nstream`n$body`nendstream`nendobj`n"
        $offs[$pid2] = $ms.Position; & $wr "$pid2 0 obj`n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents $cid 0 R /Resources << /Font << /F1 3 0 R >> >> >>`nendobj`n"
    }
    $n = 4 + 2 * $pages; $xref = $ms.Position
    & $wr "xref`n0 $n`n0000000000 65535 f `n"
    for ($i = 1; $i -lt $n; $i++) { & $wr ("{0:D10} 00000 n `n" -f $offs[$i]) }
    & $wr "trailer`n<< /Size $n /Root 1 0 R >>`nstartxref`n$xref`n%%EOF"
    [IO.File]::WriteAllBytes($Path, $ms.ToArray())
}

# ================================================================= FASE 1
function Fase1 {
    $script:CurPhase = 'F1'; Write-Host "`n=== FASE 1 - INVENTARIO INICIAL ===" -ForegroundColor Cyan
    $os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
    $null = Save-Ev 'hostname' { hostname }
    $null = Save-Ev 'systeminfo' { systeminfo }
    $null = Save-Ev 'ComputerInfo' { Get-ComputerInfo | Format-List * }
    $null = Save-Ev 'Fecha' { Get-Date -Format o }
    $null = Save-Ev 'LastBootUpTime' { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
    $null = Save-Ev 'CPU' { Get-CimInstance Win32_Processor | Format-List Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed }
    $null = Save-Ev 'RAM' { Get-CimInstance Win32_PhysicalMemory | Format-Table BankLabel, Capacity, Speed -Auto }
    $null = Save-Ev 'Volumenes' { Get-Volume | Format-Table -Auto }
    $null = Save-Ev 'Discos' { Get-Disk | Format-Table -Auto }
    $null = Save-Ev 'PhysicalDisk_SMART' { Get-PhysicalDisk | Format-List FriendlyName, MediaType, HealthStatus, OperationalStatus, Size; Get-PhysicalDisk | Get-StorageReliabilityCounter | Format-List * }
    $null = Save-Ev 'IP' { Get-NetIPAddress | Sort-Object InterfaceAlias | Format-Table InterfaceAlias, IPAddress, PrefixLength, AddressFamily -Auto }
    $null = Save-Ev 'IPConfig_Gateway' { Get-NetIPConfiguration | Format-List }
    $null = Save-Ev 'Rutas' { Get-NetRoute | Format-Table -Auto }
    $null = Save-Ev 'DNS' { Get-DnsClientServerAddress | Format-Table -Auto }
    $null = Save-Ev 'PuertosAbiertos' { Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{n = 'Proceso'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } | Sort-Object LocalPort | Format-Table -Auto }
    $null = Save-Ev 'Servicios' { Get-Service | Sort-Object Status, Name | Format-Table Name, Status, StartType -Auto }
    $null = Save-Ev 'Roles' { Get-WindowsFeature | Where-Object Installed | Format-Table Name, DisplayName -Auto }

    # Hallazgos
    $okOS = ($os.Caption -match '2025') -and ([int]$os.BuildNumber -ge 26100)
    Add-Finding 'F1' 'Sistema operativo' $(if ($okOS) { 'OK' } else { 'WARN' }) "$($os.Caption) | Build $($os.BuildNumber) | $($os.OSArchitecture)"
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
    if ($ExpectedIP) {
        if ($ips -contains $ExpectedIP) { Add-Finding 'F1' 'Dirección IP' 'OK' "Coincide con la IP esperada $ExpectedIP" }
        else {
            Add-Finding 'F1' 'Dirección IP' 'RISK' "Este equipo NO tiene la IP esperada $ExpectedIP (IPs: $($ips -join ', '))"
            if (-not $Force) { Save-State; throw "IP esperada $ExpectedIP no encontrada. Use -Force solo si está seguro de que es el equipo correcto." }
        }
    } else { Add-Finding 'F1' 'Dirección IP' 'INFO' "IP principal detectada: $ServerIP (todas: $($ips -join ', '))" }
    $up = (Get-Date) - $os.LastBootUpTime
    Add-Finding 'F1' 'Uptime' $(if ($up.TotalDays -gt 45) { 'WARN' } else { 'OK' }) ('{0:N1} días (último arranque {1})' -f $up.TotalDays, $os.LastBootUpTime)
    Add-Finding 'F1' 'Dominio' 'INFO' $(if ($cs.PartOfDomain) { "Miembro de $($cs.Domain)" } else { "Workgroup: $($cs.Domain)" })
    Add-Finding 'F1' 'Memoria RAM' 'INFO' ('{0:N1} GB totales' -f ($cs.TotalPhysicalMemory / 1GB))
    $sysDrv = $env:SystemDrive.TrimEnd(':')
    $v = Get-Volume -DriveLetter $sysDrv
    $freeGB = [math]::Round($v.SizeRemaining / 1GB, 1)
    $e = if ($freeGB -lt $MinFreeGB) { 'RISK' } elseif ($freeGB -lt $MinFreeGB * 1.5) { 'WARN' } else { 'OK' }
    Add-Finding 'F1' "Espacio libre ${sysDrv}:" $e "$freeGB GB libres de $([math]::Round($v.Size/1GB,1)) GB (mínimo $MinFreeGB GB)"
    $bad = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.HealthStatus -ne 'Healthy' })
    Add-Finding 'F1' 'Estado de discos (SMART/Storage)' $(if ($bad.Count) { 'RISK' } else { 'OK' }) $(if ($bad.Count) { ($bad | ForEach-Object { "$($_.FriendlyName)=$($_.HealthStatus)" }) -join '; ' } else { 'Todos Healthy' })
    $svc = @(Get-CimInstance Win32_Service)
    $autoStop = @($svc | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })
    Add-Finding 'F1' 'Servicios' 'INFO' "Running=$(@($svc|Where-Object State -eq 'Running').Count) Automatic=$(@($svc|Where-Object StartMode -eq 'Auto').Count) Disabled=$(@($svc|Where-Object StartMode -eq 'Disabled').Count)"
    Add-Finding 'F1' 'Servicios automáticos detenidos' $(if ($autoStop.Count) { 'WARN' } else { 'OK' }) $(if ($autoStop.Count) { ($autoStop.Name -join ', ') } else { 'Ninguno' })
    $failed = @($svc | Where-Object { $_.State -eq 'Stopped' -and $_.ExitCode -ne 0 -and $_.ExitCode -ne 1077 -and $_.StartMode -ne 'Disabled' })
    Add-Finding 'F1' 'Servicios con error de salida' $(if ($failed.Count) { 'WARN' } else { 'OK' }) $(if ($failed.Count) { ($failed | ForEach-Object { "$($_.Name)($($_.ExitCode))" }) -join ', ' } else { 'Ninguno' })
    $roles = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object Name)
    Add-Finding 'F1' 'Roles instalados' 'INFO' $(if ($roles.Count) { $roles -join ', ' } else { 'Ninguno' })
    $St.Meta.Roles = $roles
    $St.Meta.Features = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object Installed | ForEach-Object Name)

    Set-Sec 'F1' @{
        EstadoInicial = "- Hostname: $env:COMPUTERNAME`n- SO: $($os.Caption) build $($os.BuildNumber) ($($os.OSArchitecture))`n- Dominio/Workgroup: $($cs.Domain)`n- Último arranque: $($os.LastBootUpTime)`n- Disco ${sysDrv}: libre $freeGB GB"
        Accion          = 'Recolección de solo lectura (sin cambios en el servidor).'
        Resultado       = 'Inventario completo guardado en evidencias.'
        Validacion      = 'Cada dato proviene de comandos ejecutados en el servidor (ver Evidencia).'
        Rollback        = 'No aplica (solo lectura).'
        Recomendaciones = 'Contrastar el inventario con la documentación del laboratorio.'
        Conclusion      = 'Línea base registrada.'
    }
    Save-State
}

# ================================================================= FASE 2
function Fase2 {
    $script:CurPhase = 'F2'; Write-Host "`n=== FASE 2 - PRE-CHECK ===" -ForegroundColor Cyan
    $null = Save-Ev 'servicios_requeridos' { Get-Service wuauserv, BITS, CryptSvc, TrustedInstaller | Format-Table Name, Status, StartType -Auto }
    $null = Save-Ev 'CBS' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\' | Format-List }
    $null = Save-Ev 'PendingReboot_claves' { 'RebootPending=' + (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'); 'WU RebootRequired=' + (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') }
    $null = Save-Ev 'WU_politicas' { Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue | Format-List; Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue | Format-List }
    $null = Save-Ev 'DISM_CheckHealth' { Dism.exe /Online /Cleanup-Image /CheckHealth }
    $null = Save-Ev 'Conectividad' { foreach ($h in 'www.powershellgallery.com', 'www.update.microsoft.com', 'download.windowsupdate.com') { Test-NetConnection $h -Port 443 -WarningAction SilentlyContinue | Format-List ComputerName, RemotePort, TcpTestSucceeded } }

    $sysDrv = $env:SystemDrive.TrimEnd(':'); $freeGB = [math]::Round((Get-Volume -DriveLetter $sysDrv).SizeRemaining / 1GB, 1)
    Add-Finding 'F2' 'Espacio libre suficiente' $(if ($freeGB -ge $MinFreeGB) { 'OK' } else { 'RISK' }) "$freeGB GB (mínimo $MinFreeGB GB)"
    foreach ($n in 'wuauserv', 'BITS', 'CryptSvc', 'TrustedInstaller', 'msiserver') {
        $s = Get-Service $n -ErrorAction SilentlyContinue
        if (-not $s) { Add-Finding 'F2' "Servicio $n" 'RISK' 'No existe' }
        elseif ($s.StartType -eq 'Disabled') { Add-Finding 'F2' "Servicio $n" 'RISK' 'Deshabilitado' }
        else { Add-Finding 'F2' "Servicio $n" 'OK' "$($s.Status) / $($s.StartType)" }
    }
    $msi = @(Get-Process msiexec -ErrorAction SilentlyContinue)
    Add-Finding 'F2' 'Windows Installer' $(if ($msi.Count -gt 1) { 'WARN' } else { 'OK' }) $(if ($msi.Count -gt 1) { 'Hay instalaciones MSI en curso' } else { 'Sin instalaciones en curso' })
    $wsus = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    if ($wsus -and $wsus.WUServer) { Add-Finding 'F2' 'Origen de Windows Update' 'WARN' "Política WSUS: $($wsus.WUServer) (el escaneo usará WSUS)" }
    else { Add-Finding 'F2' 'Origen de Windows Update' 'OK' 'Sin política WSUS: Microsoft Update directo' }
    $dism = (Get-Content (Join-Path $EvDir 'F2_DISM_CheckHealth.txt') -Raw)
    Add-Finding 'F2' 'Almacén de componentes (DISM)' $(if ($dism -match 'No component store corruption|no se detect') { 'OK' } else { 'WARN' }) $(if ($dism -match 'No component store corruption|no se detect') { 'Sin corrupción detectada' } else { 'Revisar salida DISM en evidencia' })
    $conn = Get-Content (Join-Path $EvDir 'F2_Conectividad.txt') -Raw
    Add-Finding 'F2' 'Conectividad HTTPS (PSGallery/Update)' $(if (([regex]::Matches($conn, 'TcpTestSucceeded\s*:\s*True')).Count -ge 3) { 'OK' } else { 'WARN' }) 'Ver evidencia Conectividad'
    $rb = @(Get-PendingReboot)
    if ($rb.Count) { Add-Finding 'F2' 'Reinicio pendiente previo' 'WARN' ("$IcoWARN " + ($rb -join ', ')) } else { Add-Finding 'F2' 'Reinicio pendiente previo' 'OK' "$IcoOK No requiere reinicio" }
    $St.Meta.RebootBefore = $rb

    Set-Sec 'F2' @{
        EstadoInicial = "- Espacio libre: $freeGB GB`n- Reinicio pendiente previo: $(if($rb.Count){$rb -join ', '}else{'no'})"
        Accion          = 'Verificaciones de solo lectura (servicios, MSI, WU, CBS, DISM CheckHealth, conectividad).'
        Resultado       = 'Ver diagnóstico.'
        Validacion      = 'Claves de registro y servicios consultados directamente.'
        Rollback        = 'No aplica (solo lectura).'
        Recomendaciones = 'Si hay reinicio pendiente previo, reiniciar antes de instalar para reducir fallas de servicing.'
        Conclusion      = ''
    }
    Save-State
}

# ================================================================= FASE 3
function Fase3 {
    $script:CurPhase = 'F3'; Write-Host "`n=== FASE 3 - RESPALDOS ===" -ForegroundColor Cyan
    $bk = Join-Path $BackupDir $RunId
    New-Item -ItemType Directory -Force -Path $bk | Out-Null
    $St.Meta.BackupDir = $bk
    $do = {
        param($n, $b)
        try { & $b; Add-Finding 'F3' $n 'OK' 'Respaldo creado' } catch { Add-Finding 'F3' $n 'RISK' $_.Exception.Message }
    }
    & $do 'Firewall (netsh export)' { netsh advfirewall export "$bk\Firewall.wfw" | Out-Null; if ($LASTEXITCODE -ne 0) { throw "netsh exit $LASTEXITCODE" } }
    & $do 'Configuración de red' {
        ipconfig /all | Out-File "$bk\ipconfig_all.txt" -Encoding UTF8
        route print | Out-File "$bk\route_print.txt" -Encoding UTF8
        Get-NetIPConfiguration | Export-Clixml "$bk\NetIPConfiguration.clixml"
        Get-DnsClientServerAddress | Export-Clixml "$bk\DnsServers.clixml"
        netsh dump | Out-File "$bk\netsh_dump.txt" -Encoding UTF8
    }
    & $do 'Servicios' { Get-CimInstance Win32_Service | Select-Object Name, DisplayName, StartMode, State, PathName, StartName | Export-Csv "$bk\Servicios.csv" -NoTypeInformation -Encoding UTF8 }
    & $do 'Programador de tareas' {
        Get-ScheduledTask | Select-Object TaskPath, TaskName, State | Export-Csv "$bk\Tareas.csv" -NoTypeInformation -Encoding UTF8
        robocopy "$env:windir\System32\Tasks" "$bk\Tasks" /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "robocopy exit $LASTEXITCODE" }
    }
    & $do 'Políticas locales' {
        secedit /export /cfg "$bk\secpol.inf" /areas SECURITYPOLICY USER_RIGHTS | Out-Null
        auditpol /backup /file:"$bk\auditpol.csv" | Out-Null
        gpresult /h "$bk\gpresult.html" /f | Out-Null
        if (Test-Path "$env:windir\System32\GroupPolicy") { robocopy "$env:windir\System32\GroupPolicy" "$bk\GroupPolicy" /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null }
        $keys = @{
            Schannel = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
            LanmanServer = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            TerminalServer = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'
            PoliciesSystem = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            WUPolicies = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        }
        foreach ($k in $keys.Keys) { reg query $keys[$k] 2>$null | Out-Null; if ($LASTEXITCODE -eq 0) { reg export $keys[$k] "$bk\reg_$k.reg" /y | Out-Null } }
    }
    & $do 'Lista de KB previa' { Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy | Export-Csv "$bk\HotFix_antes.csv" -NoTypeInformation -Encoding UTF8 }
    if (($St.Meta.Features -contains 'Web-Server') -and (Get-Module -ListAvailable WebAdministration)) {
        & $do 'IIS (Backup-WebConfiguration)' { Import-Module WebAdministration; Backup-WebConfiguration -Name "PatchBackup_$RunId" | Out-Null; Copy-Item "$env:windir\System32\inetsrv\config\applicationHost.config" "$bk\applicationHost.config" -ErrorAction Stop }
    } else { Add-Finding 'F3' 'IIS' 'INFO' 'IIS no instalado: respaldo no aplica' }

    # SHA256
    try {
        $sums = Get-ChildItem $bk -Recurse -File | Get-FileHash -Algorithm SHA256 | Select-Object Hash, Path
        $sums | Export-Csv "$bk\SHA256SUMS.csv" -NoTypeInformation -Encoding UTF8
        $bad = @($sums | Where-Object { (Get-FileHash $_.Path -Algorithm SHA256).Hash -ne $_.Hash })
        Add-Finding 'F3' 'SHA256 de respaldos' $(if ($bad.Count) { 'RISK' } else { 'OK' }) "$(@($sums).Count) archivos con hash; verificación de integridad: $(if($bad.Count){'FALLÓ'}else{'correcta'})"
    } catch { Add-Finding 'F3' 'SHA256 de respaldos' 'RISK' $_.Exception.Message }
    Add-EvFile 'SHA256SUMS' "$bk\SHA256SUMS.csv" 'Get-FileHash -Algorithm SHA256 (respaldos)'
    Add-EvFile 'Carpeta_Respaldo' $bk 'Respaldos de configuración'
    Add-Finding 'F3' 'Snapshot de VM' 'INFO' 'Este script no crea snapshot del hipervisor; se recomienda uno antes de parchear'

    Set-Sec 'F3' @{
        EstadoInicial = "Sin respaldo previo de esta corrida. Destino: $bk"
        Accion          = 'Exportación de firewall, red, servicios, tareas, políticas locales/auditoría, claves de registro críticas, KB instaladas, IIS (si existe) y hash SHA256 con verificación.'
        Resultado       = 'Ver diagnóstico.'
        Validacion      = 'SHA256SUMS.csv recalculado y comparado.'
        Rollback        = "- Firewall: ${BT}netsh advfirewall import `"$bk\Firewall.wfw`"${BT}`n- Auditoría: ${BT}auditpol /restore /file:`"$bk\auditpol.csv`"${BT}`n- Política local: ${BT}secedit /configure /db C:\Windows\security\local.sdb /cfg `"$bk\secpol.inf`"${BT}`n- Registro: ${BT}reg import <archivo.reg>${BT}`n- IIS: ${BT}Restore-WebConfiguration -Name PatchBackup_$RunId${BT}`n- Parches: desinstalar KB con ${BT}wusa /uninstall /kb:<N>${BT} o restaurar snapshot de VM."
        Recomendaciones = 'Copiar C:\PatchBackup fuera del servidor y tomar snapshot de la VM antes de parchear.'
        Conclusion      = ''
    }
    Save-State
}

# ================================================================= FASE 4
function Fase4 {
    $script:CurPhase = 'F4'; Write-Host "`n=== FASE 4 - WINDOWS UPDATE ===" -ForegroundColor Cyan
    $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending)
    $St.Meta.HotfixBefore = @($hf | ForEach-Object { $_.HotFixID })
    $null = Save-Ev 'HotFix_antes' { Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn, InstalledBy -Auto }
    $last = ($hf | Where-Object InstalledOn | Select-Object -First 1).InstalledOn
    if ($last) { $d = ((Get-Date) - $last).Days; Add-Finding 'F4' 'Fecha del último parche' $(if ($d -gt 45) { 'WARN' } else { 'OK' }) "$($last.ToString('yyyy-MM-dd')) (hace $d días); KB instaladas: $($hf.Count)" }
    else { Add-Finding 'F4' 'Fecha del último parche' 'WARN' "Sin fecha disponible; KB instaladas: $($hf.Count)" }

    # PSWindowsUpdate (solo PowerShell Gallery)
    try {
        if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
            Install-Module -Name PSWindowsUpdate -Repository PSGallery -Scope AllUsers -Force -ErrorAction Stop
            $St.Meta.PSWUInstalledByScript = $true
            Add-Finding 'F4' 'PSWindowsUpdate' 'OK' 'Instalado desde PowerShell Gallery'
        } else { Add-Finding 'F4' 'PSWindowsUpdate' 'OK' 'Ya instalado' }
        $m = Get-Module -ListAvailable PSWindowsUpdate | Sort-Object Version -Descending | Select-Object -First 1
        Save-Text 'PSWindowsUpdate_modulo' ($m | Format-List Name, Version, Author, CompanyName, ModuleBase | Out-String) 'Get-Module -ListAvailable PSWindowsUpdate'
        Import-Module PSWindowsUpdate -ErrorAction Stop
    } catch {
        Add-Finding 'F4' 'PSWindowsUpdate' 'RISK' "No disponible: $($_.Exception.Message) [HRESULT $(Fmt-Hr $_.Exception)]"
        $St.Meta.WUFail = $true
        Set-Sec 'F4' @{ EstadoInicial = "KB instaladas: $($hf.Count)"; Accion = 'Intento de instalar/importar PSWindowsUpdate.'; Resultado = 'Falló.'; Validacion = 'n/a'; Rollback = 'n/a'; Recomendaciones = 'Verificar salida a www.powershellgallery.com:443 y proxy.'; Conclusion = '' }
        Save-State; return
    }
    try {
        $pend = @(Get-WindowsUpdate -ErrorAction Stop)
        $St.Meta.Pending = @($pend | Select-Object KB, Title, Size, MsrcSeverity)
        Save-Text 'Pendientes' (($pend | Select-Object KB, MsrcSeverity, Size, Title | Format-Table -Auto -Wrap | Out-String)) 'Get-WindowsUpdate'
        $null = Save-Ev 'WUHistory_previo' { Get-WUHistory -Last 30 | Format-Table -Auto }
        Add-Finding 'F4' 'Actualizaciones pendientes' $(if ($pend.Count) { 'WARN' } else { 'OK' }) "$($pend.Count) pendientes: $((($pend | ForEach-Object { if ($_.KB) { $_.KB } else { $_.Title } }) -join ', '))"
        foreach ($p in $pend) { Add-Finding 'F4' "Pendiente $($p.KB)" 'INFO' "Severidad: $(if($p.MsrcSeverity){$p.MsrcSeverity}else{'n/d'}) | $($p.Title)" }
    } catch {
        Add-Finding 'F4' 'Escaneo de actualizaciones' 'RISK' "$($_.Exception.Message) [HRESULT $(Fmt-Hr $_.Exception)]"
        $St.Meta.Pending = @(); $St.Meta.WUFail = $true
    }
    Set-Sec 'F4' @{
        EstadoInicial = "- KB instaladas: $($hf.Count)`n- Último parche: $(if($last){$last.ToString('yyyy-MM-dd')}else{'n/d'})"
        Accion          = 'Inventario de KB, instalación de PSWindowsUpdate solo desde PowerShell Gallery (si faltaba) y escaneo con Get-WindowsUpdate.'
        Resultado       = "Pendientes detectadas: $(@($St.Meta.Pending).Count)"
        Validacion      = 'Listado y severidades tomados de Get-WindowsUpdate.'
        Rollback        = 'Si el módulo fue instalado por este script: ' + "${BT}Uninstall-Module PSWindowsUpdate${BT}."
        Recomendaciones = 'Revisar las pendientes y su severidad antes de instalar.'
        Conclusion      = ''
    }
    Save-State
}

# ================================================================= FASE 5
function Fase5 {
    $script:CurPhase = 'F5'; Write-Host "`n=== FASE 5 - INSTALACIÓN CONTROLADA ===" -ForegroundColor Cyan
    $pend = @($St.Meta.Pending)
    if ($SkipInstall -or $St.Meta.WUFail -or $pend.Count -eq 0) {
        $why = if ($SkipInstall) { 'parámetro -SkipInstall' } elseif ($St.Meta.WUFail) { 'fallo previo en PSWindowsUpdate' } else { 'no hay actualizaciones pendientes' }
        Add-Finding 'F5' 'Instalación' 'INFO' "No ejecutada: $why"
        $St.Meta.Installed = @(); $St.Meta.InstallExec = $false
        Set-Sec 'F5' @{ EstadoInicial = "Pendientes: $($pend.Count)"; Accion = "Instalación omitida ($why)."; Resultado = 'Sin cambios.'; Validacion = 'n/a'; Rollback = 'No aplica.'; Recomendaciones = ''; Conclusion = '' }
        Save-State; return
    }
    $St.Meta.InstallExec = $true
    $t0 = Get-Date; $St.Meta.T0 = $t0
    Write-Host "  Instalando $($pend.Count) actualización(es) (una única ejecución)..." -ForegroundColor Yellow
    $all = @(); $exErr = $null
    try { $all = @(Install-WindowsUpdate -AcceptAll -IgnoreReboot -Confirm:$false -Verbose *>&1) } catch { $exErr = $_ }
    $t1 = Get-Date; $St.Meta.T1 = $t1
    $objs = @($all | Where-Object { $_ -isnot [System.Management.Automation.InformationalRecord] -and $_ -isnot [System.Management.Automation.ErrorRecord] -and $_.PSObject.Properties['KB'] })
    $text = ($all | Out-String -Width 250)
    if ($exErr) { $text += "`r`nEXCEPCIÓN: $($exErr.Exception.Message) [HRESULT $(Fmt-Hr $exErr.Exception)]" }
    Save-Text 'Install_salida' $text 'Install-WindowsUpdate -AcceptAll -IgnoreReboot -Confirm:$false -Verbose'
    $hist = @(Get-WUHistory -Last 100 -ErrorAction SilentlyContinue | Where-Object { $_.Date -ge $t0.AddMinutes(-2) })
    Save-Text 'WUHistory_post' (($hist | Select-Object * | Format-List | Out-String -Width 250)) 'Get-WUHistory -Last 100 | ? Date -ge inicio'
    $installed = @(); $failed = @()
    foreach ($h in $hist) {
        $st = "$($h.Result) $($h.Status)"
        $line = "$($h.KB) | $($h.Title) | $st | HRESULT: $(if($h.HResult){'0x{0:X8}' -f [int]$h.HResult}else{'n/d'})"
        if ($st -match 'Fail|Error|Abort') { $failed += $line } elseif ($st -match 'Succe|Install') { $installed += $line }
    }
    if ($hist.Count -eq 0) { foreach ($o in $objs) { $st = "$($o.Status) $($o.Result)"; $line = "$($o.KB) | $($o.Title) | $st"; if ($st -match 'Fail|Error') { $failed += $line } else { $installed += $line } } }
    $hres = @([regex]::Matches($text, '0x[0-9A-Fa-f]{8}') | ForEach-Object { $_.Value.ToUpper() } | Select-Object -Unique)
    $St.Meta.Installed = $installed; $St.Meta.Failed = $failed; $St.Meta.HResults = $hres
    $dur = $t1 - $t0
    Add-Finding 'F5' 'Hora de inicio / fin' 'INFO' "$($t0.ToString('HH:mm:ss')) / $($t1.ToString('HH:mm:ss'))"
    Add-Finding 'F5' 'Tiempo total' 'INFO' ('{0:hh\:mm\:ss}' -f $dur)
    Add-Finding 'F5' 'KB instaladas' $(if ($installed.Count) { 'OK' } else { 'WARN' }) "$($installed.Count): $(($installed | ForEach-Object { ($_ -split ' \|')[0] }) -join ', ')"
    if ($failed.Count -or $exErr) { Add-Finding 'F5' 'Errores durante la instalación' 'RISK' "$($failed.Count) fallidas. HRESULT: $(if($hres.Count){$hres -join ', '}else{'n/d'}). $(if($exErr){$exErr.Exception.Message})" }
    else { Add-Finding 'F5' 'Errores durante la instalación' 'OK' 'Sin errores registrados' }
    $rbReq = ($objs | Where-Object { $_.RebootRequired -eq $true }).Count -gt 0
    $St.Meta.InstallRebootFlag = $rbReq
    Set-Sec 'F5' @{
        EstadoInicial = "Pendientes antes de instalar: $($pend.Count)"
        Accion          = "Install-WindowsUpdate -AcceptAll -IgnoreReboot (ejecución única), $($t0.ToString('HH:mm:ss')) - $($t1.ToString('HH:mm:ss'))."
        Resultado       = "Instaladas: $($installed.Count). Fallidas: $($failed.Count).`n" + (($installed + $failed | ForEach-Object { "- $_" }) -join "`n")
        Validacion      = 'Cruce de la salida de Install-WindowsUpdate con Get-WUHistory.'
        Rollback        = "Desinstalar: ${BT}wusa /uninstall /kb:<numero> /quiet /norestart${BT} o restaurar snapshot de VM / ${BT}Dism /Online /Remove-Package${BT}."
        Recomendaciones = if ($failed.Count) { 'Revisar C:\Windows\Logs\CBS\CBS.log y WindowsUpdate.log para los códigos HRESULT listados.' } else { '' }
        Conclusion      = ''
    }
    Save-State
}

# ================================================================= FASE 6
function Fase6-Prepare {
    $script:CurPhase = 'F6'; Write-Host "`n=== FASE 6 - REINICIO CONTROLADO ===" -ForegroundColor Cyan
    $reasons = @(Get-PendingReboot)
    $wu = $false; try { $wu = [bool](Get-WURebootStatus -Silent -ErrorAction Stop) } catch {}
    $hard = @($reasons | Where-Object { $_ -ne 'PendingFileRenameOperations' })
    $need = ($hard.Count -gt 0) -or $wu
    if (-not $need) {
        Add-Finding 'F6' 'Reinicio requerido' 'OK' "$IcoOK No requiere reinicio"
        $St.Meta.RebootNeeded = $false
        return $false
    }
    $mot = ($hard + $(if ($wu) { 'Get-WURebootStatus=True' })) -join ', '
    Add-Finding 'F6' 'Reinicio requerido' 'WARN' "$IcoWARN Reinicio pendiente. Motivo: $mot"
    $St.Meta.RebootNeeded = $true; $St.Meta.RebootReason = $mot
    $St.Meta.RebootDecidedAt = Get-Date
    Set-Sec 'F6' @{
        EstadoInicial = "Reinicio pendiente. Motivo: $mot"
        Accion          = if ($AutoReboot) { 'Se programa tarea de inicio PatchMgmt-Continue y se reinicia en 60 s (shutdown /r /t 60).' } else { 'Reinicio NO automático (-AutoReboot no indicado): la corrida queda en pausa.' }
        Resultado       = "Hora de decisión: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'). Impacto: el servidor queda fuera de servicio durante el reinicio (estimado 5-15 min por la aplicación de actualizaciones)."
        Validacion      = 'Se ejecuta tras el arranque: systeminfo, Get-Service, Test-NetConnection localhost.'
        Rollback        = 'Cancelar reinicio programado: ' + "${BT}shutdown /a${BT}; tarea de continuación: ${BT}Unregister-ScheduledTask PatchMgmt-Continue${BT}."
        Recomendaciones = 'Confirmar que no hay usuarios/servicios críticos antes de reiniciar (laboratorio).'
        Conclusion      = ''
    }
    return $true
}

function Fase6-Validate {
    $script:CurPhase = 'F6'
    Write-Host "`n--- Validación tras reinicio / estado actual ---" -ForegroundColor Cyan
    if ($Continue -and $St.Meta.RebootNeeded) {
        $deadline = (Get-Date).AddSeconds(180)
        do { $stp = @(Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' -and -not $_.DelayedAutoStart }); if ($stp.Count -eq 0) { break }; Start-Sleep 10 } while ((Get-Date) -lt $deadline)
        $os = Get-CimInstance Win32_OperatingSystem
        $down = (Get-Date) - $St.Meta.RebootDecidedAt
        $St.Meta.Downtime = '{0:hh\:mm\:ss}' -f $down
        Add-Finding 'F6' 'Tiempo hasta servidor operativo' 'INFO' "$($St.Meta.Downtime) desde la decisión de reinicio (arranque: $($os.LastBootUpTime))"
        $ok = $os.LastBootUpTime -gt $St.Meta.RebootDecidedAt
        Add-Finding 'F6' 'Reinicio efectuado' $(if ($ok) { 'OK' } else { 'RISK' }) $(if ($ok) { 'LastBootUpTime posterior a la decisión' } else { 'El servidor NO se reinició' })
        Get-ScheduledTask -TaskName 'PatchMgmt-Continue' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    }
    $null = Save-Ev 'post_systeminfo' { systeminfo }
    $null = Save-Ev 'post_servicios' { Get-Service | Sort-Object Status, Name | Format-Table Name, Status, StartType -Auto }
    $null = Save-Ev 'post_TestNetConnection' { Test-NetConnection localhost | Format-List }
    $tn = Test-NetConnection localhost -WarningAction SilentlyContinue
    Add-Finding 'F6' 'Test-NetConnection localhost' $(if ($tn.PingSucceeded) { 'OK' } else { 'WARN' }) "Ping=$($tn.PingSucceeded)"
    $stp = @(Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })
    Add-Finding 'F6' 'Servicios automáticos detenidos (post)' $(if ($stp.Count) { 'WARN' } else { 'OK' }) $(if ($stp.Count) { ($stp.Name -join ', ') } else { 'Ninguno' })
    $rb = @(Get-PendingReboot | Where-Object { $_ -ne 'PendingFileRenameOperations' })
    Add-Finding 'F6' 'Reinicio pendiente (post)' $(if ($rb.Count) { 'WARN' } else { 'OK' }) $(if ($rb.Count) { $rb -join ', ' } else { 'No requiere reinicio' })
    if (-not $St.Sec.ContainsKey('F6')) {
        Set-Sec 'F6' @{ EstadoInicial = 'Sin reinicio pendiente tras la instalación.'; Accion = 'Solo validación (systeminfo, Get-Service, Test-NetConnection).'; Resultado = 'Sin indisponibilidad.'; Validacion = 'Ver diagnóstico.'; Rollback = 'No aplica.'; Recomendaciones = ''; Conclusion = '' }
    } else {
        $St.Sec['F6']['Resultado'] = $St.Sec['F6']['Resultado'] + "`nTiempo de indisponibilidad medido: $($St.Meta.Downtime)."
    }
    Save-State
}

# ================================================================= FASE 7
function Fase7 {
    $script:CurPhase = 'F7'; Write-Host "`n=== FASE 7 - VALIDACIÓN POSTERIOR ===" -ForegroundColor Cyan
    $null = Save-Ev 'HotFix_despues' { Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn -Auto }
    $before = @($St.Meta.HotfixBefore); $after = @(Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object { $_.HotFixID })
    $new = @($after | Where-Object { $_ -notin $before })
    Save-Text 'Comparacion_antes_despues' ("Antes: $($before.Count) KB`r`nDespués: $($after.Count) KB`r`nNuevas: $($new -join ', ')") 'Comparación Get-HotFix antes vs después'
    Add-Finding 'F7' 'KB antes vs después' $(if ($new.Count) { 'OK' } else { 'INFO' }) "Antes=$($before.Count) Después=$($after.Count) Nuevas=$($new -join ', ')"
    $fl = @($St.Meta.Failed)
    Add-Finding 'F7' 'Actualizaciones exitosas' 'INFO' "$(@($St.Meta.Installed).Count) según historial; $($new.Count) KB nuevas en Get-HotFix"
    Add-Finding 'F7' 'Actualizaciones fallidas' $(if ($fl.Count) { 'RISK' } else { 'OK' }) "$($fl.Count)"
    $p2 = @(); try { $p2 = @(Get-WindowsUpdate -ErrorAction Stop) } catch { Add-Finding 'F7' 'Re-escaneo' 'WARN' $_.Exception.Message }
    $St.Meta.PendingAfter = @($p2 | Select-Object KB, Title)
    Save-Text 'Pendientes_post' (($p2 | Select-Object KB, Title | Format-Table -Auto -Wrap | Out-String)) 'Get-WindowsUpdate (re-escaneo)'
    Add-Finding 'F7' 'Pendientes tras la instalación' $(if ($p2.Count) { 'WARN' } else { 'OK' }) $(if ($p2.Count) { "$($p2.Count): $((($p2 | ForEach-Object { $_.KB }) -join ', ')). Requiere un nuevo ciclo de parcheo." } else { 'Ninguna' })
    Set-Sec 'F7' @{
        EstadoInicial = "KB antes: $($before.Count)"
        Accion          = 'Get-HotFix posterior, comparación antes/después y re-escaneo de pendientes (sin instalar de nuevo).'
        Resultado       = "Nuevas KB: $(if($new.Count){$new -join ', '}else{'ninguna'}). Pendientes: $($p2.Count)."
        Validacion      = 'Comparación de listas Get-HotFix y Get-WindowsUpdate.'
        Rollback        = "${BT}wusa /uninstall /kb:<numero>${BT}"
        Recomendaciones = if ($p2.Count) { 'Ejecutar un nuevo ciclo controlado (la instalación se hizo una sola vez por diseño).' } else { '' }
        Conclusion      = ''
    }
    Save-State
}

# ================================================================= FASE 8
function Fase8 {
    $script:CurPhase = 'F8'; Write-Host "`n=== FASE 8 - HARDENING POSTERIOR (verificación) ===" -ForegroundColor Cyan
    $acc = @()
    $null = Save-Ev 'Firewall_perfiles' { Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked -Auto }
    foreach ($p in Get-NetFirewallProfile) { Add-Finding 'F8' "Firewall perfil $($p.Name)" $(if ($p.Enabled -eq 'True' -or $p.Enabled -eq $true) { 'OK' } else { 'RISK' }) "Enabled=$($p.Enabled) Inbound=$($p.DefaultInboundAction)" }
    # Defender
    try {
        $null = Save-Ev 'Defender_antes' { Get-MpComputerStatus | Format-List * }
        try { Update-MpSignature -ErrorAction Stop; $acc += 'Update-MpSignature ejecutado.' } catch { Add-Finding 'F8' 'Update-MpSignature' 'WARN' $_.Exception.Message }
        $null = Save-Ev 'Defender_despues' { Get-MpComputerStatus | Format-List * }
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Add-Finding 'F8' 'Defender protección en tiempo real' $(if ($mp.RealTimeProtectionEnabled) { 'OK' } else { 'RISK' }) "AMServiceEnabled=$($mp.AMServiceEnabled) RealTime=$($mp.RealTimeProtectionEnabled)"
        Add-Finding 'F8' 'Defender firmas' $(if ($mp.AntivirusSignatureAge -gt 7) { 'WARN' } else { 'OK' }) "Antigüedad: $($mp.AntivirusSignatureAge) días (versión $($mp.AntivirusSignatureVersion))"
    } catch { Add-Finding 'F8' 'Microsoft Defender' 'WARN' "No disponible o con error: $($_.Exception.Message)" }
    # Auditoría
    $aud = Save-Ev 'Auditoria' { auditpol /get /category:* }
    $noAud = ([regex]::Matches($aud, 'No Auditing|Sin auditor')).Count
    Add-Finding 'F8' 'Política de auditoría' $(if ($noAud -gt 20) { 'WARN' } else { 'INFO' }) "Subcategorías sin auditoría: $noAud (ver evidencia; contrastar con CIS/MS Baseline)"
    # TLS
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $tlsOut = @()
    foreach ($proto in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3') {
        foreach ($side in 'Server', 'Client') {
            $pth = "$base\$proto\$side"; $en = $null; $dis = $null
            if (Test-Path $pth) { $pp = Get-ItemProperty $pth; $en = $pp.Enabled; $dis = $pp.DisabledByDefault }
            $tlsOut += [pscustomobject]@{ Protocolo = $proto; Lado = $side; Enabled = $(if ($null -eq $en) { 'default del SO' } else { $en }); DisabledByDefault = $(if ($null -eq $dis) { 'default del SO' } else { $dis }) }
        }
    }
    Save-Text 'TLS' ($tlsOut | Format-Table -Auto | Out-String) 'Lectura de HKLM:\...\SCHANNEL\Protocols'
    foreach ($proto in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
        $on = @($tlsOut | Where-Object { $_.Protocolo -eq $proto -and "$($_.Enabled)" -eq '1' })
        Add-Finding 'F8' "Protocolo inseguro $proto" $(if ($on.Count) { 'RISK' } else { 'OK' }) $(if ($on.Count) { "Habilitado explícitamente en: $(($on.Lado) -join ', ')" } else { 'No habilitado explícitamente (valor por defecto del SO)' })
    }
    foreach ($proto in 'TLS 1.2', 'TLS 1.3') {
        $off = @($tlsOut | Where-Object { $_.Protocolo -eq $proto -and "$($_.Enabled)" -eq '0' })
        Add-Finding 'F8' "Protocolo $proto" $(if ($off.Count) { 'RISK' } else { 'OK' }) $(if ($off.Count) { "Deshabilitado explícitamente en: $(($off.Lado) -join ', ')" } else { 'No deshabilitado (default del SO: soportado)' })
    }
    # SMB
    $null = Save-Ev 'SMB' { Get-SmbServerConfiguration | Format-List EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature, EncryptData, RejectUnencryptedAccess; Get-WindowsFeature FS-SMB1 | Format-List Name, InstallState; Get-SmbConnection | Format-Table -Auto }
    $smb = Get-SmbServerConfiguration
    if ($smb.EnableSMB1Protocol) {
        if ($ApplyHardening) {
            try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false; Add-Finding 'F8' 'SMBv1' 'OK' 'Estaba habilitado: DESHABILITADO por -ApplyHardening'; $acc += 'SMBv1 deshabilitado.' } catch { Add-Finding 'F8' 'SMBv1' 'RISK' "Habilitado y no se pudo deshabilitar: $($_.Exception.Message)" }
        } else { Add-Finding 'F8' 'SMBv1' 'RISK' 'HABILITADO. Ejecute con -ApplyHardening para deshabilitarlo (nunca se habilita).' }
    } else { Add-Finding 'F8' 'SMBv1' 'OK' 'Deshabilitado' }
    Add-Finding 'F8' 'SMBv2/SMBv3' $(if ($smb.EnableSMB2Protocol) { 'OK' } else { 'RISK' }) "EnableSMB2Protocol=$($smb.EnableSMB2Protocol) (SMB3 comparte esta pila); Firma requerida=$($smb.RequireSecuritySignature)"
    # UAC
    $null = Save-Ev 'UAC' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' | Format-List EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, PromptOnSecureDesktop, FilterAdministratorToken, LocalAccountTokenFilterPolicy }
    $u = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Add-Finding 'F8' 'UAC' $(if ($u.EnableLUA -eq 1) { 'OK' } else { 'RISK' }) "EnableLUA=$($u.EnableLUA) ConsentPromptBehaviorAdmin=$($u.ConsentPromptBehaviorAdmin) SecureDesktop=$($u.PromptOnSecureDesktop)"
    if ($u.LocalAccountTokenFilterPolicy -eq 1) { Add-Finding 'F8' 'LocalAccountTokenFilterPolicy' 'WARN' 'Valor 1: desactiva el filtrado remoto de cuentas locales' }
    # RDP
    $null = Save-Ev 'RDP' {
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' | Format-List fDenyTSConnections
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Format-List UserAuthentication, SecurityLayer, MinEncryptionLevel
        Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Format-Table DisplayName, Enabled, Profile, Direction, Action -Auto
        Get-LocalGroupMember 'Remote Desktop Users' -ErrorAction SilentlyContinue | Format-Table Name, ObjectClass -Auto
        Get-LocalGroupMember 'Administrators' -ErrorAction SilentlyContinue | Format-Table Name, ObjectClass -Auto
    }
    $ts = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
    if ($ts -eq 1) { Add-Finding 'F8' 'RDP' 'OK' 'Deshabilitado (fDenyTSConnections=1)' }
    else {
        $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
        Add-Finding 'F8' 'RDP - NLA' $(if ($nla -eq 1) { 'OK' } else { 'RISK' }) "UserAuthentication=$nla"
        $fw = @(Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' })
        Add-Finding 'F8' 'RDP - Firewall' $(if ($fw.Count) { 'INFO' } else { 'WARN' }) "$($fw.Count) regla(s) de entrada habilitadas; revisar alcance (RemoteAddress) en evidencia"
        $rdu = @(Get-LocalGroupMember 'Remote Desktop Users' -ErrorAction SilentlyContinue)
        $adm = @(Get-LocalGroupMember 'Administrators' -ErrorAction SilentlyContinue)
        Add-Finding 'F8' 'RDP - Usuarios autorizados' 'INFO' "Remote Desktop Users: $(if($rdu.Count){($rdu.Name) -join ', '}else{'(vacío)'}); Administrators: $(($adm.Name) -join ', ')"
    }
    Set-Sec 'F8' @{
        EstadoInicial = 'Configuración de seguridad leída directamente del servidor.'
        Accion          = "Verificación de Firewall, Defender (Update-MpSignature), auditoría, TLS, SMB, UAC y RDP. $($acc -join ' ')"
        Resultado       = 'Ver diagnóstico. Solo se modifica lo explícitamente permitido por -ApplyHardening (deshabilitar SMBv1).'
        Validacion      = 'Relectura de las configuraciones tras cualquier cambio.'
        Rollback        = "SMBv1: no se rehabilita (política del laboratorio). Resto: sin cambios. Respaldo de políticas/registro en $($St.Meta.BackupDir)."
        Recomendaciones = 'Contrastar contra Microsoft Security Baseline y CIS Benchmark de Windows Server 2025 mediante GPO/LGPO en el laboratorio antes de aplicar cambios masivos.'
        Conclusion      = ''
    }
    Save-State
}

# ================================================================= FASE 9
function Fase9 {
    $script:CurPhase = 'F9'; Write-Host "`n=== FASE 9 - EVENT VIEWER ===" -ForegroundColor Cyan
    $since = (Get-Date).AddDays(-$EventDays)
    $sum = @()
    foreach ($d in @(@{ L = 'Security'; I = @(4624, 4625, 4672, 4719, 4720) }, @{ L = 'System'; I = @(7031, 7036) })) {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $d.L; Id = $d.I; StartTime = $since } -MaxEvents 20000 -ErrorAction SilentlyContinue)
        $csv = Join-Path $EvDir "F9_$($d.L).csv"
        $ev | Select-Object TimeCreated, Id, ProviderName, @{ n = 'Mensaje'; e = { ($_.Message -split "`r?`n")[0] } } | Export-Csv $csv -NoTypeInformation -Encoding UTF8
        Add-EvFile "Eventos_$($d.L)" $csv "Get-WinEvent -FilterHashtable @{LogName='$($d.L)';Id=$($d.I -join ',');StartTime=-${EventDays}d}"
        foreach ($i in $d.I) { $sum += [pscustomobject]@{ Log = $d.L; Id = $i; Cantidad = @($ev | Where-Object Id -eq $i).Count }; Set-Variable -Name "ev_$i" -Value @($ev | Where-Object Id -eq $i) -Scope Script }
    }
    Save-Text 'Resumen_IDs' ($sum | Format-Table -Auto | Out-String) "Conteo por Event ID, últimos $EventDays días"
    $c = @{}; foreach ($s in $sum) { $c[$s.Id] = $s.Cantidad }
    Add-Finding 'F9' '4624 Inicios de sesión correctos' 'INFO' "$($c[4624])"
    $e4625 = if ($c[4625] -gt 100) { 'RISK' } elseif ($c[4625] -gt 20) { 'WARN' } else { 'OK' }
    Add-Finding 'F9' '4625 Inicios de sesión fallidos' $e4625 "$($c[4625])"
    if ($script:ev_4625.Count) {
        $top = $script:ev_4625 | ForEach-Object { [pscustomobject]@{ Usuario = $_.Properties[5].Value; Origen = $_.Properties[19].Value } } | Group-Object Usuario, Origen | Sort-Object Count -Descending | Select-Object -First 10 Count, Name
        Save-Text 'Top_4625' ($top | Format-Table -Auto | Out-String) '4625 agrupado por usuario/origen'
        Add-Finding 'F9' 'Top orígenes de fallos (4625)' 'INFO' (($top | Select-Object -First 3 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' ; ')
    }
    Add-Finding 'F9' '4672 Privilegios especiales asignados' 'INFO' "$($c[4672])"
    Add-Finding 'F9' '4719 Cambios en política de auditoría' $(if ($c[4719]) { 'WARN' } else { 'OK' }) "$($c[4719])"
    Add-Finding 'F9' '4720 Cuentas de usuario creadas' $(if ($c[4720]) { 'WARN' } else { 'OK' }) "$($c[4720])$(if($script:ev_4720.Count){': ' + (($script:ev_4720 | ForEach-Object { $_.Properties[0].Value }) -join ', ')})"
    Add-Finding 'F9' '7031 Servicio terminó inesperadamente' $(if ($c[7031]) { 'WARN' } else { 'OK' }) "$($c[7031])"
    Add-Finding 'F9' '7036 Cambios de estado de servicios' 'INFO' "$($c[7036])"
    $s24 = (Get-Date).AddHours(-24)
    foreach ($ln in 'System', 'Application') {
        $er = @(Get-WinEvent -FilterHashtable @{ LogName = $ln; Level = 1, 2; StartTime = $s24 } -MaxEvents 2000 -ErrorAction SilentlyContinue)
        $crit = @($er | Where-Object Level -eq 1).Count
        $csv = Join-Path $EvDir "F9_${ln}_errores24h.csv"
        $er | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, @{ n = 'Mensaje'; e = { ($_.Message -split "`r?`n")[0] } } | Export-Csv $csv -NoTypeInformation -Encoding UTF8
        Add-EvFile "Errores_$ln" $csv "Get-WinEvent -FilterHashtable @{LogName='$ln';Level=1,2;StartTime=-24h}"
        $topP = ($er | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '; '
        Add-Finding 'F9' "$ln (24 h) críticos/errores" $(if ($crit) { 'RISK' } elseif ($er.Count) { 'WARN' } else { 'OK' }) "Críticos=$crit Errores=$($er.Count)$(if($topP){' | Top: '+$topP})"
    }
    Set-Sec 'F9' @{
        EstadoInicial = "Ventana de análisis: últimos $EventDays días (errores: 24 h)."
        Accion          = 'Lectura de Security (4624, 4625, 4672, 4719, 4720) y System (7031, 7036); errores/críticos de System y Application.'
        Resultado       = 'Resumen técnico en el diagnóstico; CSV completos en evidencias.'
        Validacion      = 'Conteos obtenidos con Get-WinEvent sobre los registros reales.'
        Rollback        = 'No aplica (solo lectura).'
        Recomendaciones = 'Investigar picos de 4625, cualquier 4720/4719 no planificado y reinicios inesperados de servicios (7031).'
        Conclusion      = ''
    }
    Save-State
}

# ================================================================= FASE 10
function Fase10 {
    $script:CurPhase = 'F10'; Write-Host "`n=== FASE 10 - VALIDACIÓN OPERATIVA ===" -ForegroundColor Cyan
    $feat = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object Installed | ForEach-Object Name)
    $null = Save-Ev 'Roles_actuales' { Get-WindowsFeature | Where-Object Installed | Format-Table Name, DisplayName -Auto }
    $newF = @($feat | Where-Object { $_ -notin @($St.Meta.Features) }); $lostF = @(@($St.Meta.Features) | Where-Object { $_ -notin $feat })
    Add-Finding 'F10' 'Roles/características vs inventario inicial' $(if ($newF.Count -or $lostF.Count) { 'WARN' } else { 'OK' }) $(if ($newF.Count -or $lostF.Count) { "Nuevas: $($newF -join ',') Faltantes: $($lostF -join ',')" } else { 'Sin cambios' })
    foreach ($n in 'EventLog', 'RpcSs', 'W32Time', 'Dnscache', 'LanmanServer', 'LanmanWorkstation', 'mpssvc', 'WinDefend', 'TermService') {
        $s = Get-Service $n -ErrorAction SilentlyContinue
        if ($s) { $e = if ($s.Status -eq 'Running') { 'OK' } elseif ($s.StartType -eq 'Disabled') { 'INFO' } else { 'WARN' }; Add-Finding 'F10' "Servicio crítico $n" $e "$($s.Status) / $($s.StartType)" }
    }
    $chk = @(
        @{ F = 'Web-Server'; N = 'IIS'; S = @('W3SVC', 'WAS') },
        @{ F = 'DNS'; N = 'DNS'; S = @('DNS') },
        @{ F = 'DHCP'; N = 'DHCP'; S = @('DHCPServer') },
        @{ F = 'AD-Domain-Services'; N = 'Active Directory'; S = @('NTDS', 'Netlogon', 'KDC') },
        @{ F = 'FS-FileServer'; N = 'Archivos compartidos'; S = @('LanmanServer') }
    )
    foreach ($c in $chk) {
        if ($feat -notcontains $c.F) { Add-Finding 'F10' $c.N 'INFO' 'Rol no instalado: no se valida'; continue }
        foreach ($sn in $c.S) { $s = Get-Service $sn -ErrorAction SilentlyContinue; Add-Finding 'F10' "$($c.N) - servicio $sn" $(if ($s -and $s.Status -eq 'Running') { 'OK' } else { 'RISK' }) $(if ($s) { "$($s.Status)" } else { 'No existe' }) }
        switch ($c.F) {
            'Web-Server' { $null = Save-Ev 'IIS' { Import-Module WebAdministration; Get-Website | Format-Table Name, State, PhysicalPath -Auto; Get-WebAppPoolState | Format-Table -Auto }; $ws = @(Get-Website -ErrorAction SilentlyContinue | Where-Object State -ne 'Started'); Add-Finding 'F10' 'IIS - sitios detenidos' $(if ($ws.Count) { 'WARN' } else { 'OK' }) $(if ($ws.Count) { ($ws.Name -join ', ') } else { 'Ninguno' }) }
            'DNS' { $null = Save-Ev 'DNS' { Get-DnsServerZone | Format-Table -Auto; Resolve-DnsName localhost -ErrorAction SilentlyContinue | Format-Table -Auto } }
            'DHCP' { $null = Save-Ev 'DHCP' { Get-DhcpServerv4Scope | Format-Table -Auto } }
            'AD-Domain-Services' { $null = Save-Ev 'AD_dcdiag' { dcdiag /q } }
            'FS-FileServer' { $null = Save-Ev 'Shares' { Get-SmbShare | Format-Table Name, Path, Description -Auto } }
        }
    }
    Set-Sec 'F10' @{
        EstadoInicial = "Roles/características instaladas: $($feat.Count)."
        Accion          = 'Validación de servicios críticos y de los roles realmente instalados (sin asumir roles inexistentes).'
        Resultado       = 'Ver diagnóstico.'
        Validacion      = 'Estados leídos con Get-Service, Get-WindowsFeature y cmdlets propios de cada rol.'
        Rollback        = 'No aplica (solo lectura).'
        Recomendaciones = ''
        Conclusion      = ''
    }
    Save-State
}

# ================================================================= FASE 11
$HealthScript = @'
#Requires -Version 5.1
# HealthCheck.ps1 - generado por Invoke-PatchManagement.ps1 (se ejecuta cada 5 min)
$ErrorActionPreference = 'SilentlyContinue'
$dir = 'C:\PatchManagement\HealthCheck'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$script:f = @()
function Chk($n, $e, $d) { $script:f += [pscustomobject]@{ Check = $n; Estado = $e; Detalle = $d } }
function Hi($v, $w, $r) { if ($v -ge $r) { 'RISK' } elseif ($v -ge $w) { 'WARN' } else { 'OK' } }
function Lo($v, $w, $r) { if ($v -le $r) { 'RISK' } elseif ($v -le $w) { 'WARN' } else { 'OK' } }

$os = Get-CimInstance Win32_OperatingSystem
$cpu = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average, 1)
Chk 'CPU' (Hi $cpu 75 90) "$cpu %"
$ram = [math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
Chk 'RAM' (Hi $ram 80 90) "$ram % en uso"
$dsk = ''
foreach ($v in Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }) {
    $pct = [math]::Round($v.SizeRemaining / $v.Size * 100, 1); $gb = [math]::Round($v.SizeRemaining / 1GB, 1)
    Chk "Disco $($v.DriveLetter):" (Lo $pct 20 10) "$pct % libre ($gb GB)"
    if ($v.DriveLetter -eq 'C') { $dsk = $pct }
}
$fwOff = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
Chk 'Firewall' $(if ($fwOff.Count) { 'RISK' } else { 'OK' }) $(if ($fwOff.Count) { 'Deshabilitado: ' + ($fwOff.Name -join ',') } else { 'Todos los perfiles habilitados' })
$mp = Get-MpComputerStatus
if ($mp) {
    $e = if (-not $mp.RealTimeProtectionEnabled) { 'RISK' } elseif ($mp.AntivirusSignatureAge -gt 7) { 'WARN' } else { 'OK' }
    Chk 'Defender' $e "RealTime=$($mp.RealTimeProtectionEnabled) Firmas=$($mp.AntivirusSignatureAge) d"
} else { Chk 'Defender' 'WARN' 'No disponible' }
$ws = Get-Service wuauserv, BITS, CryptSvc
$wsBad = @($ws | Where-Object { $_.StartType -eq 'Disabled' })
$lastHf = (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
$days = if ($lastHf) { ((Get-Date) - $lastHf).Days } else { 9999 }
$srch = $null; try { $srch = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate } catch {}
Chk 'Windows Update' $(if ($wsBad.Count) { 'RISK' } elseif ($days -gt 45) { 'WARN' } else { 'OK' }) "Último parche hace $days d; última búsqueda: $srch; servicios deshabilitados: $($wsBad.Name -join ',')"
$ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; Level = 1, 2; StartTime = (Get-Date).AddHours(-1) } -MaxEvents 200)
$cr = @($ev | Where-Object Level -eq 1).Count
Chk 'Eventos críticos (1 h)' $(if ($cr) { 'RISK' } elseif ($ev.Count) { 'WARN' } else { 'OK' }) "Críticos=$cr Errores=$($ev.Count - $cr)"
$ign = 'sppsvc', 'RemoteRegistry', 'MapsBroker', 'edgeupdate', 'edgeupdatem', 'CDPSvc', 'TrustedInstaller', 'wuauserv', 'BITS', 'gupdate', 'gupdatem', 'tiledatamodelsvc'
$up = (Get-Date) - $os.LastBootUpTime
$st = @(Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' -and $ign -notcontains $_.Name -and -not ($_.DelayedAutoStart -and $up.TotalMinutes -lt 10) })
Chk 'Servicios automáticos' $(if ($st.Count) { 'WARN' } else { 'OK' }) $(if ($st.Count) { 'Detenidos: ' + ($st.Name -join ', ') } else { 'Todos en ejecución' })
if (Get-Service W3SVC) {
    $w3 = (Get-Service W3SVC).Status; $sites = ''
    try { Import-Module WebAdministration; $bad = @(Get-Website | Where-Object State -ne 'Started'); $sites = "sitios detenidos: $($bad.Count)" } catch {}
    Chk 'IIS' $(if ($w3 -ne 'Running') { 'RISK' } else { 'OK' }) "W3SVC=$w3 $sites"
} else { Chk 'IIS' 'OK' 'No instalado' }
$rb = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $rb += 'CBS' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rb += 'WU' }
Chk 'Reinicio pendiente' $(if ($rb.Count) { 'WARN' } else { 'OK' }) $(if ($rb.Count) { 'Pendiente: ' + ($rb -join ',') } else { 'No requiere reinicio' })

$overall = if ($script:f | Where-Object Estado -eq 'RISK') { 'RISK' } elseif ($script:f | Where-Object Estado -eq 'WARN') { 'WARN' } else { 'OK' }
$res = [pscustomobject]@{ Fecha = (Get-Date).ToString('o'); Servidor = $env:COMPUTERNAME; Estado = $overall; Checks = $script:f }
$res | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $dir 'health_latest.json') -Encoding UTF8
$hist = Join-Path $dir 'health_history.csv'
[pscustomobject]@{ Fecha = $res.Fecha; Estado = $overall; CPU = $cpu; RAM = $ram; DiscoC_Libre_Pct = $dsk } | Export-Csv $hist -Append -NoTypeInformation -Encoding UTF8
$l = @(Get-Content $hist); if ($l.Count -gt 5000) { $l[0] + "`r`n" + (($l | Select-Object -Last 4000) -join "`r`n") | Set-Content $hist -Encoding UTF8 }
exit $(switch ($overall) { 'OK' { 0 } 'WARN' { 1 } default { 2 } })
'@

function Fase11 {
    $script:CurPhase = 'F11'; Write-Host "`n=== FASE 11 - HEALTH CHECK ===" -ForegroundColor Cyan
    $hs = Join-Path $ScriptsDir 'HealthCheck.ps1'
    Set-Content -Path $hs -Value $HealthScript -Encoding UTF8
    Add-EvFile 'HealthCheck.ps1' $hs 'Creación de HealthCheck.ps1'
    $err = $null
    try {
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$hs`""
        $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
        $pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $set = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 4)
        Register-ScheduledTask -TaskName 'HealthCheck-5min' -Action $act -Trigger $trg -Principal $pri -Settings $set -Force -Description 'Health Check cada 5 minutos (Patch Management)' | Out-Null
        Add-Finding 'F11' 'Tarea programada HealthCheck-5min' 'OK' 'Registrada (SYSTEM, cada 5 min)'
    } catch { $err = $_; Add-Finding 'F11' 'Tarea programada HealthCheck-5min' 'RISK' $_.Exception.Message }
    $null = Save-Ev 'Tarea_info' { Get-ScheduledTask -TaskName 'HealthCheck-5min' | Get-ScheduledTaskInfo | Format-List; (Get-ScheduledTask -TaskName 'HealthCheck-5min').Triggers | Format-List Repetition, StartBoundary }
    # Ejecución inmediata de validación
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $hs | Out-Null
    $code = $LASTEXITCODE
    $json = Join-Path $BaseDir 'HealthCheck\health_latest.json'
    if (Test-Path $json) {
        $h = Get-Content $json -Raw | ConvertFrom-Json
        Add-EvFile 'health_latest' $json 'HealthCheck.ps1 (ejecución inmediata)'
        Add-Finding 'F11' 'Health Check (ejecución inmediata)' $(switch ($h.Estado) { 'OK' { 'OK' } 'WARN' { 'WARN' } default { 'RISK' } }) "Estado global: $($h.Estado) (exit $code)"
        foreach ($c in $h.Checks) { Add-Finding 'F11' $c.Check $c.Estado $c.Detalle }
    } else { Add-Finding 'F11' 'Health Check (ejecución inmediata)' 'RISK' 'No generó health_latest.json' }
    Set-Sec 'F11' @{
        EstadoInicial = 'Sin Health Check previo.'
        Accion          = "Creación de $hs y tarea HealthCheck-5min (SYSTEM, cada 5 min). Ejecución inmediata."
        Resultado       = "Salida continua en $BaseDir\HealthCheck (health_latest.json y health_history.csv)."
        Validacion      = 'Se ejecutó el script una vez y se leyó su resultado.'
        Rollback        = "${BT}Unregister-ScheduledTask HealthCheck-5min -Confirm:`$false${BT}; ${BT}Remove-Item $hs${BT}"
        Recomendaciones = 'Si el laboratorio cuenta con monitoreo central, enviar health_latest.json.'
        Conclusion      = ''
    }
    Save-State
}

# ================================================================= FASE 12 + INFORME FINAL
function Fase12 {
    $script:CurPhase = 'F12'; Write-Host "`n=== FASE 12 - INFORMES ===" -ForegroundColor Cyan
    Write-PhaseReport 'Inventario.md'    'Inventario' @('F1')
    Write-PhaseReport 'PreCheck.md'      'Pre-Check y Respaldos' @('F2', 'F3')
    Write-PhaseReport 'WindowsUpdate.md' 'Windows Update, Instalación y Reinicio' @('F4', 'F5', 'F6')
    Write-PhaseReport 'Hardening.md'     'Hardening posterior' @('F8')
    Write-PhaseReport 'Eventos.md'       'Event Viewer' @('F9')
    Write-PhaseReport 'Validacion.md'    'Validación posterior y operativa' @('F7', 'F10')
    Write-PhaseReport 'HealthCheck.md'   'Health Check' @('F11')

    $all = @($St.Findings); $c = @{ OK = 0; WARN = 0; RISK = 0 }
    foreach ($x in $all) { if ($c.ContainsKey($x.Estado)) { $c[$x.Estado]++ } }
    $end = Get-Date; $dur = $end - $St.Start
    $w = Get-Worst $all
    $inst = @($St.Meta.Installed); $fail = @($St.Meta.Failed); $pa = @($St.Meta.PendingAfter)
    $os = Get-CimInstance Win32_OperatingSystem
    $exec = Get-ReportHeader 'Informe Final - Patch Management Windows Server 2025' @('F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11')
    $exec += @"
## Resumen ejecutivo

| Concepto | Valor |
|---|---|
| Servidor | $env:COMPUTERNAME ($ServerIP) |
| Sistema operativo | $($os.Caption) build $($os.BuildNumber) |
| Inicio / Fin | $($St.Start.ToString('yyyy-MM-dd HH:mm:ss')) / $($end.ToString('yyyy-MM-dd HH:mm:ss')) |
| Duración total (incluye reinicio) | $('{0:hh\:mm\:ss}' -f $dur) |
| Actualizaciones pendientes detectadas | $(@($St.Meta.Pending).Count) |
| KB instaladas | $($inst.Count) |
| Actualizaciones fallidas | $($fail.Count) |
| Códigos HRESULT registrados | $(if(@($St.Meta.HResults).Count){@($St.Meta.HResults) -join ', '}else{'ninguno'}) |
| Reinicio requerido | $(if($St.Meta.RebootNeeded){'Sí - ' + $St.Meta.RebootReason + ' - indisponibilidad: ' + $St.Meta.Downtime}else{'No'}) |
| Pendientes tras el parcheo | $($pa.Count) |
| Hallazgos | $IcoOK Correcto: $($c.OK) / $IcoWARN Advertencia: $($c.WARN) / $IcoRISK Riesgo: $($c.RISK) |
| Estado global | $(Ico $w) $w |

### KB instaladas

$(if($inst.Count){($inst | ForEach-Object { "- $_" }) -join "`n"}else{'- Ninguna en esta corrida.'})

### Hallazgos con Advertencia / Riesgo

$(($all | Where-Object { $_.Estado -in 'WARN','RISK' } | ForEach-Object { "- $(Ico $_.Estado) [$($_.Fase)] **$($_.Item)**: $($_.Detalle)" }) -join "`n")

"@
    $detail = ''
    foreach ($p in $PhaseTitle.Keys) { if ($St.Sec.ContainsKey($p)) { $detail += (Get-PhaseMd $p '##') + "`r`n" } }
    $md = $exec + "`r`n# Detalle por fase`r`n`r`n" + $detail
    $mdPath = Join-Path $BaseDir 'Informe_Final.md'; $htPath = Join-Path $BaseDir 'Informe_Final.html'; $pdfPath = Join-Path $BaseDir 'Informe_Final.pdf'
    Set-Content -Path $mdPath -Value $md -Encoding UTF8
    Set-Content -Path $htPath -Value (ConvertTo-HtmlDoc $md 'Informe Final - Patch Management') -Encoding UTF8
    # PDF: Edge/Chrome headless si existen; si no, generador PDF interno
    $br = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    $pdfOk = $false
    if ($br) {
        try {
            if (Test-Path $pdfPath) { Remove-Item $pdfPath -Force }
            $p = Start-Process $br -ArgumentList '--headless', '--disable-gpu', '--no-pdf-header-footer', "--print-to-pdf=`"$pdfPath`"", "`"file:///$($htPath -replace '\\','/')`"" -PassThru -WindowStyle Hidden
            $null = $p.WaitForExit(90000)
            $pdfOk = (Test-Path $pdfPath) -and ((Get-Item $pdfPath).Length -gt 1000)
        } catch {}
    }
    if (-not $pdfOk) { New-SimplePdf -Text $md -Path $pdfPath; Write-Host '  PDF generado con el generador interno (texto plano, Courier).' -ForegroundColor Yellow }
    # Hash de informes y evidencias
    Get-ChildItem $BaseDir -Include '*.md', '*.html', '*.pdf' -Recurse -File | Where-Object { $_.FullName -notmatch 'Run_' } | Get-FileHash -Algorithm SHA256 | Select-Object Hash, Path | Export-Csv (Join-Path $EvDir 'SHA256SUMS_informes.csv') -NoTypeInformation -Encoding UTF8
    Get-ChildItem $EvDir -File | Where-Object Name -ne 'SHA256SUMS_evidencias.csv' | Get-FileHash -Algorithm SHA256 | Select-Object Hash, Path | Export-Csv (Join-Path $EvDir 'SHA256SUMS_evidencias.csv') -NoTypeInformation -Encoding UTF8
    $St.Stage = 'done'; Save-State
}

function Show-Final {
    $f = @($St.Findings)
    $ok = [char]0x2714; $no = [char]0x2718
    function L($txt, $phases) { $w = Get-Worst ($f | Where-Object { $phases -contains $_.Fase }); $m = if ($w -eq 'RISK') { $no } else { $ok }; $c = @{ OK = 'Green'; WARN = 'Yellow'; RISK = 'Red' }[$w]; Write-Host ("  {0} {1}  {2}" -f $m, $txt, (Ico $w)) -ForegroundColor $c }
    $rep = 'Inventario.md', 'PreCheck.md', 'WindowsUpdate.md', 'Hardening.md', 'Eventos.md', 'Validacion.md', 'HealthCheck.md', 'Informe_Final.md', 'Informe_Final.html', 'Informe_Final.pdf'
    $docs = -not ($rep | Where-Object { -not (Test-Path (Join-Path $BaseDir $_)) })
    Write-Host "`n==========================================================" -ForegroundColor Cyan
    Write-Host "`n   PATCH MANAGEMENT`n   WINDOWS SERVER 2025`n`n   Administrador: $Responsable`n   Servidor: $ServerIP ($env:COMPUTERNAME)`n"
    L 'Inventario Inicial' @('F1'); L 'Pre-Check' @('F2'); L 'Backups' @('F3'); L 'Windows Update' @('F4')
    L 'Instalación de KB' @('F5'); L 'Reinicio Validado' @('F6'); L 'Hardening' @('F8'); L 'Auditoría' @('F8'); L 'Event Viewer' @('F9')
    L 'Health Check' @('F11'); L 'Validación Operativa' @('F7', 'F10')
    Write-Host ("  {0} Documentación" -f $(if ($docs) { $ok } else { $no })) -ForegroundColor $(if ($docs) { 'Green' } else { 'Red' })
    Write-Host "`n==========================================================" -ForegroundColor Cyan
    $upd = (@($St.Meta.Failed).Count -eq 0) -and (@($St.Meta.PendingAfter).Count -eq 0) -and -not $St.Meta.WUFail -and -not $SkipInstall
    $val = (Get-Worst ($f | Where-Object { $_.Fase -in 'F6', 'F7', 'F10' })) -ne 'RISK'
    $hard = (Get-Worst ($f | Where-Object { $_.Fase -eq 'F8' })) -ne 'RISK'
    $noCrit = (Get-Worst $f) -ne 'RISK'
    Write-Host "`n  ESTADO FINAL`n"
    Write-Host ("  {0}" -f $(if ($upd) { 'SERVIDOR ACTUALIZADO' } else { 'ACTUALIZACIÓN INCOMPLETA (fallidas/pendientes/omitida) - ver informe' })) -ForegroundColor $(if ($upd) { 'Green' } else { 'Yellow' })
    Write-Host ("  {0}" -f $(if ($val) { 'SERVIDOR VALIDADO' } else { 'VALIDACIÓN CON RIESGOS' })) -ForegroundColor $(if ($val) { 'Green' } else { 'Red' })
    Write-Host ("  {0}" -f $(if ($hard) { 'SERVIDOR ENDURECIDO (sin riesgos en verificación)' } else { 'HARDENING CON RIESGOS PENDIENTES' })) -ForegroundColor $(if ($hard) { 'Green' } else { 'Red' })
    Write-Host ("  {0}" -f $(if ($noCrit) { 'SIN ERRORES CRÍTICOS' } else { 'EXISTEN HALLAZGOS DE RIESGO' })) -ForegroundColor $(if ($noCrit) { 'Green' } else { 'Red' })
    Write-Host ("  {0}" -f $(if ($docs) { 'DOCUMENTACIÓN COMPLETA' } else { 'DOCUMENTACIÓN INCOMPLETA' })) -ForegroundColor $(if ($docs) { 'Green' } else { 'Red' })
    Write-Host "`n  Informes: $BaseDir`n  Evidencias: $EvDir`n  Respaldos: $($St.Meta.BackupDir)`n"
    Write-Host "  Marcelo Gallardo | Autor | Investigador | Ingeniero en Sistemas`n  https://panivinux.base44.app/`n" -ForegroundColor Cyan
    Write-Host '==========================================================' -ForegroundColor Cyan
}

# ================================================================= FLUJO PRINCIPAL
try {
    if (-not $Continue) {
        Fase1; Fase2; Fase3; Fase4; Fase5
        $needReboot = Fase6-Prepare
        if ($needReboot) {
            $St.Stage = 'awaiting-reboot'; Save-State
            if ($AutoReboot) {
                $expArg = if ($ExpectedIP) { "-ExpectedIP $ExpectedIP " } else { '' }
                $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Continue $expArg-Responsable `"$Responsable`" -BaseDir `"$BaseDir`" -BackupDir `"$BackupDir`" -ScriptsDir `"$ScriptsDir`" -MinFreeGB $MinFreeGB -EventDays $EventDays"
                if ($ApplyHardening) { $arg += ' -ApplyHardening' }
                if ($Force) { $arg += ' -Force' }
                $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
                $trg = New-ScheduledTaskTrigger -AtStartup; $trg.Delay = 'PT2M'
                $pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                Register-ScheduledTask -TaskName 'PatchMgmt-Continue' -Action $act -Trigger $trg -Principal $pri -Force | Out-Null
                Write-Host "`n  Reinicio en 60 s. La corrida continuará automáticamente (tarea PatchMgmt-Continue). Cancelar: shutdown /a" -ForegroundColor Yellow
                Stop-Transcript | Out-Null
                shutdown.exe /r /t 60 /c 'Patch Management: reinicio controlado' /d p:2:17
                exit 0
            } else {
                Write-Host "`n  REINICIO PENDIENTE. Reinicie el servidor y luego ejecute:`n  .\$(Split-Path $ScriptPath -Leaf) -Continue" -ForegroundColor Yellow
                Stop-Transcript | Out-Null
                exit 0
            }
        }
    }
    Fase6-Validate
    Fase7; Fase8; Fase9; Fase10; Fase11
    Fase12
    Show-Final
} catch {
    Write-Host "ERROR FATAL: $($_.Exception.Message) [HRESULT $(Fmt-Hr $_.Exception)]" -ForegroundColor Red
    try { Save-State } catch {}
    throw
} finally {
    try { Stop-Transcript | Out-Null } catch {}
}
