<#
.SYNOPSIS
    Diagnóstico de SOLO LECTURA: por qué Windows no reconoce bien una memoria USB.
    No cambia nada: no monta, no formatea, no quita protecciones.

.DESCRIPTION
    Reúne en un archivo de texto:
      - Discos, particiones y volúmenes (estado, solo lectura, fuera de línea, salud).
      - Política de montaje de discos nuevos (SAN). Si quedó en OfflineAll,
        Windows deja los USB nuevos FUERA DE LÍNEA y parecen "con error".
      - Dispositivos USB / de disco con códigos de problema del Administrador de dispositivos.
      - Eventos recientes del sistema relacionados con discos y USB.
      - Estado del kit: ADK, carpeta C:\WinPE_USBForense y marcadores del USB forense.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Diagnosticar-USB.ps1
#>
param(
    [string]$Salida = '',
    [int]$HorasEventos = 48
)
$ErrorActionPreference = 'Continue'
# En Windows PowerShell 5.1 $PSScriptRoot no existe en los valores por defecto de param()
if (-not $Salida) { $Salida = Join-Path (Split-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Path -Parent) -Parent) 'diagnostico_usb.txt' }
$lineas = New-Object System.Collections.Generic.List[string]
function Add-Seccion {
    param([string]$T)
    $lineas.Add('')
    $lineas.Add(('=' * 70))
    $lineas.Add($T)
    $lineas.Add(('=' * 70))
}
function Add-Texto {
    param($Objeto)
    $texto = $Objeto | Out-String -Width 220
    foreach ($l in ($texto -split "`r?`n")) {
        if ($l.TrimEnd() -ne '') { $lineas.Add($l.TrimEnd()) }
    }
}

$esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Seccion 'EQUIPO'
$lineas.Add(('Fecha: {0}   Equipo: {1}   Administrador: {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $env:COMPUTERNAME, $esAdmin))
try { $os = Get-CimInstance Win32_OperatingSystem; $lineas.Add(('Windows: {0} {1} (build {2})' -f $os.Caption, $os.Version, $os.BuildNumber)) } catch { }

Add-Seccion 'POLÍTICA DE DISCOS NUEVOS (SAN)'
try {
    $pol = [string](Get-StorageSetting -ErrorAction Stop).NewDiskPolicy
    $lineas.Add("NewDiskPolicy = $pol")
    if ($pol -eq 'OfflineAll') { $lineas.Add('>>> PROBLEMA PROBABLE: con OfflineAll Windows deja TODO disco nuevo (incluidos USB) fuera de línea.') }
} catch { $lineas.Add('No se pudo leer (requiere administrador): ' + $_.Exception.Message) }

Add-Seccion 'DISCOS'
$discos = @()
try {
    $discos = @(Get-Disk -ErrorAction Stop | Sort-Object Number)
    $tabla = foreach ($d in $discos) {
        $firma = ''
        if ($null -ne $d.Signature) { $firma = '{0:X8}' -f [uint32]$d.Signature }
        [pscustomobject]@{
            N = $d.Number; Modelo = $d.FriendlyName; Bus = $d.BusType; GB = [math]::Round($d.Size / 1073741824, 1)
            Estilo = $d.PartitionStyle; Estado = $d.OperationalStatus; Salud = $d.HealthStatus
            FueraLinea = $d.IsOffline; Motivo = $d.OfflineReason; SoloLectura = $d.IsReadOnly
            Arranque = $d.IsBoot; Sistema = $d.IsSystem; Firma = $firma
        }
    }
    Add-Texto ($tabla | Format-Table -AutoSize)
    foreach ($d in $discos | Where-Object { [string]$_.BusType -eq 'USB' }) {
        if ($d.IsOffline) { $lineas.Add(('>>> El disco USB #{0} está FUERA DE LÍNEA (motivo: {1}).' -f $d.Number, $d.OfflineReason)) }
        if ($d.IsReadOnly) { $lineas.Add(('>>> El disco USB #{0} tiene el atributo SOLO LECTURA.' -f $d.Number)) }
        if ([string]$d.PartitionStyle -eq 'RAW') { $lineas.Add(('>>> El disco USB #{0} no tiene tabla de particiones (RAW).' -f $d.Number)) }
        if ([string]$d.HealthStatus -ne 'Healthy') { $lineas.Add(('>>> El disco USB #{0} reporta salud: {1}.' -f $d.Number, $d.HealthStatus)) }
    }
    if (-not ($discos | Where-Object { [string]$_.BusType -eq 'USB' })) { $lineas.Add('>>> Windows NO ve ningún disco USB conectado.') }
} catch { $lineas.Add('Get-Disk falló: ' + $_.Exception.Message) }

Add-Seccion 'PARTICIONES Y VOLÚMENES DE DISCOS USB'
foreach ($d in $discos | Where-Object { [string]$_.BusType -eq 'USB' }) {
    $lineas.Add(('-- Disco #{0} {1}' -f $d.Number, $d.FriendlyName))
    try {
        $parts = @(Get-Partition -DiskNumber $d.Number -ErrorAction Stop)
        Add-Texto ($parts | Select-Object -Property @('PartitionNumber', 'DriveLetter', 'Size', 'Type', 'IsActive', 'IsHidden') | Format-Table -AutoSize)
        foreach ($p in $parts) {
            try {
                $v = Get-Volume -Partition $p -ErrorAction Stop
                $lineas.Add(('   Part {0}: letra={1} etiqueta="{2}" FS={3} salud={4} estado={5} libre={6:N1} GB' -f $p.PartitionNumber, $v.DriveLetter, $v.FileSystemLabel, $v.FileSystem, $v.HealthStatus, $v.OperationalStatus, ($v.SizeRemaining / 1GB)))
                if (-not $v.DriveLetter -and $v.FileSystem) { $lineas.Add(('   >>> La partición {0} tiene sistema de archivos pero NO tiene letra asignada.' -f $p.PartitionNumber)) }
                if (-not $v.FileSystem) { $lineas.Add(('   >>> La partición {0} no tiene sistema de archivos reconocible (RAW).' -f $p.PartitionNumber)) }
            } catch { $lineas.Add(('   Part {0}: sin volumen legible ({1})' -f $p.PartitionNumber, $_.Exception.Message)) }
        }
    } catch { $lineas.Add('   Sin particiones legibles: ' + $_.Exception.Message) }
}

Add-Seccion 'UNIDADES CON LETRA'
foreach ($u in [System.IO.DriveInfo]::GetDrives()) {
    $ok = $false; try { $ok = $u.IsReady } catch { }
    $marca = ''
    if ($ok) {
        if (Test-Path -LiteralPath (Join-Path $u.Name 'USB-FORENSE.marker')) { $marca += ' [HERRAMIENTAS del USB forense]' }
        if (Test-Path -LiteralPath (Join-Path $u.Name 'RESPALDO.marker')) { $marca += ' [RESPALDO del USB forense]' }
        if (Test-Path -LiteralPath (Join-Path $u.Name 'sources\boot.wim')) { $marca += ' [arranque WinPE]' }
        $lineas.Add(('{0} tipo={1} FS={2} etiqueta="{3}" lista={4}{5}' -f $u.Name, $u.DriveType, $u.DriveFormat, $u.VolumeLabel, $ok, $marca))
    } else { $lineas.Add(('{0} tipo={1} lista=False (no accesible)' -f $u.Name, $u.DriveType)) }
}

Add-Seccion 'ADMINISTRADOR DE DISPOSITIVOS (USB y discos con problemas)'
try {
    $dev = @(Get-PnpDevice -ErrorAction Stop | Where-Object { @('USB', 'DiskDrive', 'Volume', 'SCSIAdapter', 'HIDClass') -contains [string]$_.Class -or $_.InstanceId -like 'USBSTOR*' })
    $mal = @($dev | Where-Object { [string]$_.Status -ne 'OK' -and [string]$_.Status -ne 'Unknown' })
    if ($mal.Count -eq 0) { $lineas.Add('Ningún dispositivo USB/disco presente reporta error.') }
    else { Add-Texto ($mal | Select-Object -Property @('Status', 'Class', 'FriendlyName', 'ConfigManagerErrorCode', 'InstanceId') | Format-Table -AutoSize) }
    $lineas.Add('Almacenamiento USB presente:')
    Add-Texto ($dev | Where-Object { $_.InstanceId -like 'USBSTOR*' -and $_.Present } | Select-Object -Property @('Status', 'FriendlyName', 'InstanceId') | Format-Table -AutoSize)
} catch { $lineas.Add('Get-PnpDevice falló: ' + $_.Exception.Message) }

Add-Seccion ("EVENTOS DEL SISTEMA (últimas $HorasEventos h: disco, NTFS, USB, particiones)")
try {
    $desde = (Get-Date).AddHours(-$HorasEventos)
    $prov = @('disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'volmgr', 'partmgr', 'Microsoft-Windows-Partition', 'USBHUB3', 'Microsoft-Windows-USB-USBHUB3', 'Microsoft-Windows-Kernel-PnP', 'Microsoft-Windows-StorPort', 'stornvme', 'Microsoft-Windows-DriverFrameworks-UserMode', 'volsnap', 'Microsoft-Windows-Kernel-IO')
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $desde; Level = 1, 2, 3 } -ErrorAction Stop | Where-Object { $prov -contains $_.ProviderName } | Select-Object -First 60)
    if ($ev.Count -eq 0) { $lineas.Add('Sin errores ni advertencias de esos orígenes.') }
    foreach ($e in $ev) {
        $msg = ([string]$e.Message -replace '\s+', ' ').Trim()
        if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
        $lineas.Add(('{0:yyyy-MM-dd HH:mm} [{1}] {2} ID {3}: {4}' -f $e.TimeCreated, $e.LevelDisplayName, $e.ProviderName, $e.Id, $msg))
    }
} catch { $lineas.Add('No se pudieron leer los eventos: ' + $_.Exception.Message) }

Add-Seccion 'KIT USB FORENSE EN ESTE PC'
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Assessment and Deployment Kit'
$lineas.Add(('ADK Deployment Tools: {0}' -f (Test-Path -LiteralPath (Join-Path $kits 'Deployment Tools\DandISetEnv.bat'))))
$lineas.Add(('Complemento WinPE:   {0}' -f (Test-Path -LiteralPath (Join-Path $kits 'Windows Preinstallation Environment\amd64\WinPE_OCs'))))
$t = 'C:\WinPE_USBForense'
$lineas.Add(('Carpeta de trabajo {0}: {1}' -f $t, (Test-Path -LiteralPath $t)))
foreach ($f in @('usb-id.txt', 'manifest.sha256', 'referencia_winpe.sha256', 'HUELLA-ANCLA.txt')) {
    $p = Join-Path $t $f
    if (Test-Path -LiteralPath $p) {
        $extra = ''
        if ($f -eq 'usb-id.txt' -or $f -eq 'HUELLA-ANCLA.txt') { $extra = ' -> ' + ((Get-Content -LiteralPath $p -Raw) -replace '\s+', ' ').Trim() }
        $lineas.Add("  $f existe$extra")
    } else { $lineas.Add("  $f NO existe") }
}
if (Test-Path -LiteralPath (Join-Path $t 'winpe\mount\Windows')) { $lineas.Add('  >>> Hay una imagen boot.wim MONTADA de un intento anterior (C:\WinPE_USBForense\winpe\mount).') }
try {
    $mi = (& (Join-Path $env:SystemRoot 'System32\dism.exe') /Get-MountedImageInfo 2>&1 | Out-String)
    if ($mi -match 'Mount Dir') { $lineas.Add('Imágenes montadas por DISM:'); Add-Texto $mi }
} catch { }

Add-Seccion 'POSIBLES CAUSAS DETECTADAS'
$causas = @($lineas | Where-Object { $_ -like '*>>>*' })
if ($causas.Count -eq 0) { $lineas.Add('No se detectó una causa evidente. Indique el mensaje de error exacto.') } else { foreach ($c in $causas) { $lineas.Add($c.Trim()) } }

[System.IO.File]::WriteAllLines($Salida, [string[]]$lineas, (New-Object System.Text.UTF8Encoding($true)))
Write-Host "Diagnóstico guardado en: $Salida" -ForegroundColor Green
