#Requires -RunAsAdministrator
<#
.SYNOPSIS
    OPCIONAL - Segunda opinión con Microsoft Defender. Se usa en un PC SANO con
    Windows 10/11 al que se conecta el disco del equipo dañado (adaptador o
    caja USB para SATA/NVMe).

.DESCRIPTION
    - Pone el disco en SOLO LECTURA antes de montar sus volúmenes.
    - Actualiza las firmas de Defender.
    - Escanea cada volumen con MpCmdRun -DisableRemediation: Defender SOLO
      informa; no pone en cuarentena, no limpia y no borra nada.
    - Guarda las detecciones en RESPALDO:\Entrada\detecciones_externas.csv.
      Analizar-Equipo.ps1 las importa (por número de serie de volumen + ruta
      relativa) y pone esos archivos en la cuarentena del USB.

    Microsoft Defender Offline (el análisis que se lanza desde "Seguridad de
    Windows") solo analiza el PC desde el que se ejecuta, por eso no sirve
    para un equipo que no arranca. Esta es la alternativa equivalente.
#>
param([string]$Salida, [string]$Trabajo = 'C:\WinPE_USBForense')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Manifiesto.ps1')

Write-Paso 'Estado de Microsoft Defender'
$st = Get-MpComputerStatus
Write-Host ('Antivirus activo: {0} | Modo: {1} | Firmas: {2}' -f $st.AntivirusEnabled, $st.AMRunningMode, $st.AntivirusSignatureLastUpdated)
if (-not $st.AMServiceEnabled) { throw 'El servicio de Microsoft Defender no está activo en este PC.' }
try { Update-MpSignature -ErrorAction Stop; Write-Host 'Firmas de Defender actualizadas.' -ForegroundColor Green }
catch { Write-Host ('No se pudieron actualizar las firmas: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }

$mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
$plat = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
if (Test-Path -LiteralPath $plat) {
    $ult = Get-ChildItem -LiteralPath $plat -Directory | Sort-Object Name -Descending | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'MpCmdRun.exe') } | Select-Object -First 1
    if ($ult) { $mp = Join-Path $ult.FullName 'MpCmdRun.exe' }
}
if (-not (Test-Path -LiteralPath $mp)) { throw 'No se encontró MpCmdRun.exe.' }

Write-Paso 'Política de montaje de discos nuevos'
$pol = [string](Get-StorageSetting).NewDiskPolicy
Write-Host "Política actual: $pol"
if ($pol -ne 'OfflineAll') {
    Write-Host 'Para que Windows NO monte (ni escriba en) el disco al conectarlo, la política debe ser OfflineAll.' -ForegroundColor Yellow
    if ((Read-Host 'Escriba SI para aplicarla ahora (se revierte al final)') -eq 'SI') {
        Set-StorageSetting -NewDiskPolicy OfflineAll
        Write-Host 'Aplicada.' -ForegroundColor Green
    }
}
Read-Host 'Conecte ahora el disco del equipo dañado (si no lo ha hecho) y pulse Enter'
Start-Sleep -Seconds 5

Write-Paso 'Selección del disco'
$usbForense = $null; $usbInfo = $null
try { $usbInfo = Get-UsbForense -Trabajo $Trabajo; $usbForense = $usbInfo.Disco } catch { Write-Host 'USB forense no conectado o no identificado (no es obligatorio aquí).' -ForegroundColor Gray }
$cand = @(Get-Disk | Where-Object { -not $_.IsSystem -and -not $_.IsBoot -and $_.Number -ne $usbForense } | Sort-Object Number)
if ($cand.Count -eq 0) { throw 'No se ve ningún disco externo candidato.' }
foreach ($d in $cand) { Write-Host ('  Disco {0}: {1}  {2:N1} GB  bus {3}  {4}' -f $d.Number, $d.FriendlyName, ($d.Size / 1GB), $d.BusType, $d.OperationalStatus) }
$num = [int](Read-Host 'Número del disco a analizar')
if (-not ($cand | Where-Object { $_.Number -eq $num })) { throw 'Número no válido.' }
if ((Read-Host ("Se pondrá el disco {0} en SOLO LECTURA. Escriba SI" -f $num)) -ne 'SI') { throw 'Cancelado.' }

$d = Get-Disk -Number $num
if (-not $d.IsOffline) { Set-Disk -Number $num -IsOffline $true }
Set-Disk -Number $num -IsReadOnly $true
Set-Disk -Number $num -IsOffline $false
Start-Sleep -Seconds 4
if (-not (Get-Disk -Number $num).IsReadOnly) { throw 'No se pudo poner el disco en solo lectura.' }
Write-Host 'Disco en SOLO LECTURA.' -ForegroundColor Green

$letras = @()
foreach ($p in @(Get-Partition -DiskNumber $num)) {
    $c = [int][char]$p.DriveLetter
    if ($c -eq 0 -and @('Basic', 'IFS') -contains [string]$p.Type -and $p.Size -gt 512MB) {
        try { Add-PartitionAccessPath -DiskNumber $num -PartitionNumber $p.PartitionNumber -AssignDriveLetter; $p = Get-Partition -DiskNumber $num -PartitionNumber $p.PartitionNumber; $c = [int][char]$p.DriveLetter } catch { }
    }
    if ($c -ne 0) { $letras += ('{0}:' -f [char]$c) }
}
foreach ($l in $letras) {
    try {
        $bl = Get-BitLockerVolume -MountPoint $l -ErrorAction Stop
        if ([string]$bl.LockStatus -eq 'Locked') {
            # Entrada oculta: la clave no queda en pantalla ni en el historial
            $ss = Read-Host "El volumen $l está bloqueado por BitLocker. Clave de recuperación (Enter para omitir)" -AsSecureString
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
            try { $k = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            if ($k) { Unlock-BitLocker -MountPoint $l -RecoveryPassword $k.Trim() | Out-Null }
            $k = $null
        }
    } catch { }
}
$letras = @($letras | Where-Object { Test-Path -LiteralPath "$_\" })
if ($letras.Count -eq 0) { throw 'Ningún volumen legible.' }

if (-not $Salida) {
    # Solo en el USB identificado por firma (no en un marcador que pudiera estar en el disco analizado)
    if ($usbInfo) { $Salida = "$($usbInfo.R)\Entrada" } else { $Salida = Join-Path $env:USERPROFILE 'Desktop\Defender_Analisis' }
}
New-Item -ItemType Directory -Path $Salida -Force | Out-Null

Write-Paso ('Escaneando {0} con Microsoft Defender (solo informar, sin remediar)' -f ($letras -join ', '))
$filas = New-Object System.Collections.Generic.List[string]
$filas.Add('SerieVolumen;Letra;RutaRelativa;Firma;Motor;Fecha')
$total = 0
foreach ($l in $letras) {
    $vol = Get-CimInstance -ClassName Win32_Volume -Filter ("DriveLetter='{0}'" -f $l)
    $serie = [string]([uint32]$vol.SerialNumber)
    $log = Join-Path $Salida ('defender_{0}_{1}.log' -f $l.Substring(0, 1), (Get-Date -Format 'yyyyMMdd_HHmm'))
    Write-Host "Escaneando $l ... (puede tardar horas)"
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $out = & $mp -Scan -ScanType 3 -File ("$l\") -DisableRemediation 2>&1 | ForEach-Object { [string]$_ }
    $codigo = $LASTEXITCODE
    $ErrorActionPreference = $eap
    [System.IO.File]::WriteAllLines($log, [string[]]$out)
    Write-Host ("  MpCmdRun terminó con código {0} (0 = limpio, 2 = amenazas o error). Registro: {1}" -f $codigo, $log)
    $amenaza = $null
    foreach ($linea in $out) {
        if ($linea -match '^\s*Threat\s*:\s*(.+)$') { $amenaza = $Matches[1].Trim(); continue }
        if ($amenaza -and $linea -match '^\s+\w+\s*:\s*([A-Za-z]:\\.+)$') {
            $ruta = $Matches[1].Trim()
            $ruta = ($ruta -split '->')[0].Trim()                # miembro de un comprimido -> el contenedor
            if ($ruta.Substring(0, 2) -ine $l) { continue }
            $rel = $ruta.Substring(3)
            $campos = @($serie, $l, $rel, $amenaza, 'Microsoft Defender', (Get-Date -Format 's')) | ForEach-Object {
                $s = [string]$_; if ($s -match '[;"]') { '"' + $s.Replace('"', '""') + '"' } else { $s }
            }
            $filas.Add(($campos -join ';'))
            $total++
            Write-Host ("  DETECTADO: {0} [{1}]" -f $ruta, $amenaza) -ForegroundColor Magenta
        }
    }
}
$csv = Join-Path $Salida 'detecciones_externas.csv'
[System.IO.File]::WriteAllLines($csv, [string[]]$filas, (New-Object System.Text.UTF8Encoding($true)))
Write-Host ''
Write-Host ("Detecciones: {0}. Archivo: {1}" -f $total, $csv) -ForegroundColor Cyan

Write-Paso 'Cierre'
Set-Disk -Number $num -IsOffline $true
Write-Host 'Disco puesto fuera de línea: ya puede desconectarlo.' -ForegroundColor Green
if ($pol -ne 'OfflineAll' -and [string](Get-StorageSetting).NewDiskPolicy -eq 'OfflineAll') {
    Set-StorageSetting -NewDiskPolicy $pol
    Write-Host "Política de discos restaurada a $pol." -ForegroundColor Green
}
Write-Host ("El atributo de solo lectura de ese disco queda guardado en este PC. Para quitarlo en el futuro: Set-Disk -Number {0} -IsReadOnly `$false" -f $num)
