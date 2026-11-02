#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Construye el USB forense booteable (WinPE + herramientas + partición de respaldo).
    Se ejecuta en un PC TÉCNICO SANO con Windows 10/11, el Windows ADK y el
    complemento WinPE instalados.

.DESCRIPTION
    1. Prepara la carpeta HERRAMIENTAS (scripts + ClamAV portable + smartctl).
    2. Genera el manifiesto SHA-256 y su huella.
    3. Crea WinPE con copype, agrega PowerShell, WMI, Storage WMI, BitLocker...
    4. Ajusta la imagen: espacio temporal 512 MB, política SAN "OfflineAll"
       (ningún disco se monta solo), ancla de integridad y startnet.cmd.
    5. Particiona el USB (BORRA TODO): WINPE (FAT32) | HERRAMIENTAS (NTFS) | RESPALDO (NTFS).
    6. Escribe WinPE con MakeWinPEMedia (/bootex = medios firmados con CA 2023).
    7. Copia herramientas, descarga firmas de ClamAV y verifica todo.

.EXAMPLE
    .\Crear-USB.ps1 -ClamAVZip C:\Descargas\clamav-1.5.2.win.x64.zip -Smartctl 'C:\Program Files\smartmontools\bin\smartctl.exe'
#>
param(
    [Parameter(Mandatory = $true)][string]$ClamAVZip,
    [string]$Smartctl,
    [string]$Controladores,
    [int]$DiscoUSB = -1,
    [string]$Trabajo = 'C:\WinPE_USBForense',
    [int]$TamanoWinPEMB = 2048,
    [int]$TamanoHerramientasMB = 8192,
    [ValidateSet('2023', '2011')][string]$CertificadoArranque = '2023',
    [switch]$SinActualizarFirmas,
    # SHA-256 publicado del ZIP de ClamAV (página de descargas / GitHub). Recomendado.
    [string]$ClamAVSha256,
    # Paquete .msu de actualización acumulativa para la versión de WinPE (Microsoft Update Catalog)
    [string]$ActualizacionAcumulada,
    # Solo si los binarios de ClamAV no traen firma Authenticode de Cisco y usted verificó el ZIP por otra vía
    [switch]$PermitirClamAVSinFirma,
    # Nombre de la memoria: se usa en las etiquetas de las 3 particiones
    [ValidatePattern('^[A-Za-z0-9_-]{1,6}$')][string]$Nombre = 'TITAN'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Manifiesto.ps1')
$repo = Split-Path -Path $PSScriptRoot -Parent

# Desactiva el "modo de edición rápida" de la consola: así un clic dentro de la
# ventana ya no deja el proceso en pausa ("Seleccionar ...").
function Disable-EdicionRapida {
    $firma = @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetStdHandle(int n);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetConsoleMode(IntPtr h, out uint m);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleMode(IntPtr h, uint m);
'@
    try {
        $k = Add-Type -MemberDefinition $firma -Name 'ConsolaKitUsb' -Namespace 'KitUsb' -PassThru -ErrorAction Stop
        $h = $k::GetStdHandle(-10)
        $m = [uint32]0
        if ($k::GetConsoleMode($h, [ref]$m)) {
            $nuevo = ([int64]$m -bor 128) -band [int64]4294967231
            [void]$k::SetConsoleMode($h, [uint32]$nuevo)
        }
    } catch { }
}
Disable-EdicionRapida

# Registro completo en la carpeta del kit (para revisar cualquier fallo)
$logCrear = Join-Path $repo 'crear_usb_log.txt'
try { Start-Transcript -Path $logCrear -Force | Out-Null } catch { }
trap {
    Write-Host ''
    Write-Host ('ERROR: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host ('  en la línea {0}: {1}' -f $_.InvocationInfo.ScriptLineNumber, ([string]$_.InvocationInfo.Line).Trim()) -ForegroundColor Red
    Write-Host ('Registro completo: {0}' -f $logCrear) -ForegroundColor Yellow
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

# ---------------------------------------------------------------------------
# Rutas del ADK
# ---------------------------------------------------------------------------
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Assessment and Deployment Kit'
$dandi = Join-Path $kits 'Deployment Tools\DandISetEnv.bat'
$ocs = Join-Path $kits 'Windows Preinstallation Environment\amd64\WinPE_OCs'
$dirWinPE = Join-Path $Trabajo 'winpe'
$dirMontaje = Join-Path $dirWinPE 'mount'
$dirStage = Join-Path $Trabajo 'Herramientas'
$archManifiesto = Join-Path $Trabajo 'manifest.sha256'

function Invoke-EnAdk {
    # Ejecuta un comando dentro del entorno "Deployment and Imaging Tools".
    param([string]$Comando)
    # cmd /c "call "<bat>" >nul && <comando>"  -> cmd quita solo las comillas externas
    $linea = '/c "call "{0}" >nul && {1}"' -f $dandi, $Comando
    # Se espera SOLO a cmd.exe. "Start-Process -Wait" espera también a los procesos
    # auxiliares que DISM deja vivos mientras hay una imagen montada, y se cuelga.
    Write-Host ('  [ADK] {0}' -f $Comando) -ForegroundColor DarkGray
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = $linea
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    $codigo = $p.ExitCode
    $p.Dispose()
    Write-Host ('  [ADK] código de salida: {0}' -f $codigo) -ForegroundColor DarkGray
    return $codigo
}

function Assert-Codigo {
    param([int]$Codigo, [string]$Que)
    # 3010 = correcto, requiere reinicio (DISM); en una imagen sin conexión no aplica
    if ($Codigo -ne 0 -and $Codigo -ne 3010) { throw ("Falló: {0} (código {1})" -f $Que, $Codigo) }
}

# ---------------------------------------------------------------------------
Write-Paso '1/9 Comprobaciones previas'
if (-not (Test-Path -LiteralPath $dandi)) { throw 'No se encontró el Windows ADK (Deployment Tools). Instálelo desde https://learn.microsoft.com/windows-hardware/get-started/adk-install' }
if (-not (Test-Path -LiteralPath $ocs)) { throw 'No se encontró el complemento WinPE del ADK. Instale "Windows PE add-on for the ADK".' }
if (-not (Test-Path -LiteralPath $ClamAVZip)) { throw "No existe $ClamAVZip" }
if ($ActualizacionAcumulada -and -not (Test-Path -LiteralPath $ActualizacionAcumulada)) { throw "No existe $ActualizacionAcumulada" }
# Cadena de suministro: integridad del ZIP descargado
# Sin firma Authenticode, la ÚNICA garantía de origen es el hash publicado: es obligatorio
if ($PermitirClamAVSinFirma -and -not $ClamAVSha256) { throw '-PermitirClamAVSinFirma exige -ClamAVSha256 (hash publicado del ZIP).' }
if ($ClamAVSha256) {
    $hz = (Get-FileHash -LiteralPath $ClamAVZip -Algorithm SHA256).Hash
    if ($hz -ne $ClamAVSha256.Trim().ToUpperInvariant()) { throw "El SHA-256 del ZIP de ClamAV ($hz) no coincide con el publicado. No lo use." }
    Write-Host 'SHA-256 del ZIP de ClamAV verificado.' -ForegroundColor Green
} else {
    Write-Host 'AVISO: no se indicó -ClamAVSha256; se confiará en la firma Authenticode de los binarios.' -ForegroundColor Yellow
}
# Identidad única del USB: firma de disco MBR aleatoria (criptográfica) que se
# sella en el ancla. WinPE solo habilitará escritura en el disco con esta firma.
$rngId = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$bytesId = New-Object byte[] 4
do { $rngId.GetBytes($bytesId); $idNum = [System.BitConverter]::ToUInt32($bytesId, 0) } while ($idNum -eq 0 -or $idNum -eq [uint32]::MaxValue)
$rngId.Dispose()
$idUsb = '{0:X8}' -f $idNum
foreach ($f in @('Ancla\Iniciar.ps1', 'Ancla\startnet.cmd', 'Ancla\unattend.xml', 'Herramientas\Scripts\Analizar-Equipo.ps1')) {
    if (-not (Test-Path -LiteralPath (Join-Path $repo $f))) { throw "Falta $f en el kit" }
}
New-Item -ItemType Directory -Path $Trabajo -Force | Out-Null
Write-Host "ADK: $kits"
Write-Host "Carpeta de trabajo: $Trabajo"

# ---------------------------------------------------------------------------
Write-Paso '2/9 Preparando la carpeta HERRAMIENTAS (scripts + ClamAV + smartctl)'
if (Test-Path -LiteralPath $dirStage) { Remove-Item -LiteralPath $dirStage -Recurse -Force }
Copy-Item -LiteralPath (Join-Path $repo 'Herramientas') -Destination $dirStage -Recurse -Force
$tmpZip = Join-Path $Trabajo 'clamav_extraido'
if (Test-Path -LiteralPath $tmpZip) { Remove-Item -LiteralPath $tmpZip -Recurse -Force }
if ((Get-Item -LiteralPath $ClamAVZip).PSIsContainer) {
    Copy-Item -LiteralPath $ClamAVZip -Destination $tmpZip -Recurse
} else {
    Expand-Archive -LiteralPath $ClamAVZip -DestinationPath $tmpZip -Force
}
$clamscan = Get-ChildItem -LiteralPath $tmpZip -Recurse -Filter 'clamscan.exe' | Select-Object -First 1
if (-not $clamscan) { throw 'El ZIP de ClamAV no contiene clamscan.exe' }
$origenClam = $clamscan.DirectoryName
$destClam = Join-Path $dirStage 'ClamAV'
foreach ($it in @(Get-ChildItem -LiteralPath $origenClam -Force)) {
    if ($it.Name -ieq 'database' -or $it.Name -ieq 'freshclam.conf') { continue }
    Copy-Item -LiteralPath $it.FullName -Destination $destClam -Recurse -Force
}
New-Item -ItemType Directory -Path (Join-Path $destClam 'database') -Force | Out-Null
# WinPE no trae el runtime de Visual C++: se copia junto a ClamAV (despliegue local)
foreach ($dll in @('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll')) {
    $dst = Join-Path $destClam $dll
    if (-not (Test-Path -LiteralPath $dst)) {
        $src = Join-Path $env:windir "System32\$dll"
        if (-not (Test-Path -LiteralPath $src)) { throw "Falta $dll. Instale 'Microsoft Visual C++ 2015-2022 Redistributable (x64)' en este PC y repita." }
        Copy-Item -LiteralPath $src -Destination $dst
    }
}
Remove-Item -LiteralPath $tmpZip -Recurse -Force

# Cadena de suministro: firmas Authenticode de lo que se va a ejecutar en WinPE
foreach ($b in @('clamscan.exe', 'freshclam.exe', 'sigtool.exe', 'libclamav.dll')) {
    $rb = Join-Path $destClam $b
    if (-not (Test-Path -LiteralPath $rb)) { throw "Falta $b en ClamAV" }
    if (Test-FirmaAuthenticode -Ruta $rb -Sujeto 'Cisco') { Write-Host "  Firma válida (Cisco): $b" -ForegroundColor Green }
    elseif ($PermitirClamAVSinFirma) { Write-Host "  AVISO: $b sin firma válida de Cisco (permitido por parámetro)" -ForegroundColor Yellow }
    else { throw "$b no tiene firma Authenticode válida de Cisco. Descargue ClamAV solo de clamav.net/GitHub oficial. Si verificó el ZIP con -ClamAVSha256 y aun así no está firmado, use -PermitirClamAVSinFirma." }
}
foreach ($dll in @('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll')) {
    if (-not (Test-FirmaAuthenticode -Ruta (Join-Path $destClam $dll) -Sujeto 'Microsoft')) { throw "$dll no tiene firma válida de Microsoft." }
}
if ($Smartctl) {
    if (-not (Test-Path -LiteralPath $Smartctl)) { throw "No existe $Smartctl" }
    if (-not (Test-FirmaAuthenticode -Ruta $Smartctl -Sujeto '')) {
        Write-Host 'AVISO: smartctl.exe no tiene firma Authenticode. Úselo solo si lo descargó del sitio oficial de smartmontools.' -ForegroundColor Yellow
        if ((Read-Host 'Escriba SI para incluirlo igualmente') -ne 'SI') { $Smartctl = $null }
    }
    if ($Smartctl) { Copy-Item -LiteralPath $Smartctl -Destination (Join-Path $dirStage 'Smartmontools\smartctl.exe') -Force }
}
Write-Host ('ClamAV copiado desde {0}' -f $origenClam)

# ---------------------------------------------------------------------------
Write-Paso '3/9 Generando el manifiesto SHA-256 (ancla de integridad)'
$n = New-Manifiesto -Raiz $dirStage -Salida $archManifiesto
$huella = Get-HuellaManifiesto $archManifiesto
Write-Host ("{0} archivos en el manifiesto. Huella: {1}" -f $n, $huella) -ForegroundColor Green

# ---------------------------------------------------------------------------
Write-Paso '4/9 Creando la imagen WinPE (copype)'
if (Test-Path -LiteralPath $dirWinPE) {
    $r = Read-Host "Ya existe $dirWinPE. Escriba SI para borrarla y recrearla"
    if ($r -ne 'SI') { throw 'Cancelado.' }
    # Por si quedó montada de un intento anterior (se ignora el error si no lo estaba)
    [void](Invoke-EnAdk ('dism /Unmount-Image /MountDir:"{0}" /Discard >nul 2>&1' -f $dirMontaje))
    [void](Invoke-EnAdk 'dism /Cleanup-Mountpoints >nul 2>&1')
    Remove-Item -LiteralPath $dirWinPE -Recurse -Force
}
Assert-Codigo (Invoke-EnAdk ('copype amd64 "{0}"' -f $dirWinPE)) 'copype'

# ---------------------------------------------------------------------------
Write-Paso '5/9 Personalizando boot.wim (componentes, política SAN, ancla)'
$wim = Join-Path $dirWinPE 'media\sources\boot.wim'
Assert-Codigo (Invoke-EnAdk ('dism /Mount-Image /ImageFile:"{0}" /Index:1 /MountDir:"{1}"' -f $wim, $dirMontaje)) 'montar boot.wim'
$montada = $true
try {
    $paquetes = @('WinPE-WMI', 'WinPE-NetFX', 'WinPE-Scripting', 'WinPE-PowerShell', 'WinPE-StorageWMI', 'WinPE-SecureStartup', 'WinPE-EnhancedStorage')
    foreach ($p in $paquetes) {
        foreach ($cab in @((Join-Path $ocs "$p.cab"), (Join-Path $ocs "en-us\${p}_en-us.cab"))) {
            if (-not (Test-Path -LiteralPath $cab)) { Write-Host "  (no existe $cab, se omite)" -ForegroundColor DarkYellow; continue }
            Write-Host "  + $([System.IO.Path]::GetFileName($cab))"
            Assert-Codigo (Invoke-EnAdk ('dism /Image:"{0}" /Add-Package /PackagePath:"{1}"' -f $dirMontaje, $cab)) "agregar $cab"
        }
    }
    if ($ActualizacionAcumulada) {
        # Parches de seguridad de WinPE (kernel, analizadores de registro y archivos):
        # el entorno procesa datos de un equipo comprometido y debe estar al día.
        Write-Host "  + actualización acumulativa $ActualizacionAcumulada"
        Assert-Codigo (Invoke-EnAdk ('dism /Image:"{0}" /Add-Package /PackagePath:"{1}"' -f $dirMontaje, $ActualizacionAcumulada)) 'actualización acumulativa'
        Assert-Codigo (Invoke-EnAdk ('dism /Image:"{0}" /Cleanup-Image /StartComponentCleanup /ResetBase' -f $dirMontaje)) 'limpieza de componentes'
    } else {
        Write-Host '  AVISO: sin -ActualizacionAcumulada, WinPE queda con los parches de la fecha del ADK.' -ForegroundColor Yellow
    }
    Assert-Codigo (Invoke-EnAdk ('dism /Image:"{0}" /Set-ScratchSpace:512' -f $dirMontaje)) 'espacio temporal'

    if ($Controladores) {
        Write-Host "  + controladores desde $Controladores (deben estar firmados para Secure Boot)"
        Assert-Codigo (Invoke-EnAdk ('dism /Image:"{0}" /Add-Driver /Driver:"{1}" /Recurse' -f $dirMontaje, $Controladores)) 'agregar controladores'
    }

    # Política SAN: 3 = OfflineAll -> ningún disco se monta automáticamente.
    $hive = Join-Path $dirMontaje 'Windows\System32\config\SYSTEM'
    $reg = Get-RutaSistema 'reg.exe'
    & $reg load 'HKLM\WPE_SYS' $hive | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo cargar el registro de la imagen.' }
    try {
        & $reg add 'HKLM\WPE_SYS\ControlSet001\Services\partmgr\Parameters' /v SanPolicy /t REG_DWORD /d 3 /f | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'No se pudo fijar SanPolicy.' }
    } finally {
        [GC]::Collect()
        & $reg unload 'HKLM\WPE_SYS' | Out-Null
    }

    $ancla = Join-Path $dirMontaje 'Ancla'
    New-Item -ItemType Directory -Path $ancla -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $repo 'Ancla\Iniciar.ps1') -Destination $ancla -Force
    Copy-Item -LiteralPath $archManifiesto -Destination (Join-Path $ancla 'manifest.sha256') -Force
    Copy-Item -LiteralPath (Join-Path $repo 'Ancla\unattend.xml') -Destination (Join-Path $ancla 'unattend.xml') -Force
    [System.IO.File]::WriteAllText((Join-Path $ancla 'usb-id.txt'), $idUsb)
    Copy-Item -LiteralPath (Join-Path $repo 'Ancla\startnet.cmd') -Destination (Join-Path $dirMontaje 'Windows\System32\startnet.cmd') -Force

    Assert-Codigo (Invoke-EnAdk ('dism /Unmount-Image /MountDir:"{0}" /Commit' -f $dirMontaje)) 'guardar boot.wim'
    $montada = $false
} finally {
    if ($montada) {
        Write-Host 'Error: se descarta la imagen montada.' -ForegroundColor Red
        [void](Invoke-EnAdk ('dism /Unmount-Image /MountDir:"{0}" /Discard' -f $dirMontaje))
    }
}

# ---------------------------------------------------------------------------
Write-Paso '6/9 Particionando el USB (SE BORRA TODO SU CONTENIDO)'
$usbs = @(Get-Disk | Where-Object { [string]$_.BusType -eq 'USB' -and -not $_.IsSystem -and -not $_.IsBoot } | Sort-Object Number)
if ($usbs.Count -eq 0) { throw 'No se encontró ninguna memoria USB conectada.' }
foreach ($d in $usbs) { Write-Host ('  Disco {0}: {1}  {2:N1} GB' -f $d.Number, $d.FriendlyName, ($d.Size / 1GB)) }
if ($DiscoUSB -lt 0) { $DiscoUSB = [int](Read-Host 'Número de disco del USB') }
$usb = $usbs | Where-Object { $_.Number -eq $DiscoUSB } | Select-Object -First 1
if (-not $usb) { throw "El disco $DiscoUSB no es un USB válido de la lista." }
$minimo = [int64]($TamanoWinPEMB + $TamanoHerramientasMB) * 1MB + 8GB
if ($usb.Size -lt $minimo) { throw ('El USB es demasiado pequeño (mínimo {0:N0} GB).' -f ($minimo / 1GB)) }
Write-Host ''
Write-Host ('Se BORRARÁ TODO el disco {0} ({1}, {2:N1} GB).' -f $DiscoUSB, $usb.FriendlyName, ($usb.Size / 1GB)) -ForegroundColor Yellow
Write-Host ('Para confirmar escriba:  BORRAR {0}' -f $DiscoUSB) -ForegroundColor Yellow
$conf = [string](Read-Host 'Confirmación')
# Se ignoran mayúsculas/minúsculas y espacios de más, pero se exige la palabra y el número correcto
$normal = ($conf -replace '\s+', ' ').Trim().ToUpperInvariant()
Write-Host ('  Recibido: "{0}"' -f $conf)
if ($normal -ne ('BORRAR {0}' -f $DiscoUSB) -and $normal -ne ('BORRAR{0}' -f $DiscoUSB)) { throw ('Cancelado: se esperaba "BORRAR {0}" y se recibió "{1}". No se tocó el disco.' -f $DiscoUSB, $conf) }

$usadas = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
$libres = @('P', 'Q', 'S', 'T', 'U', 'V', 'W', 'Y', 'Z', 'N', 'O', 'M', 'L', 'K', 'J') | Where-Object { $usadas -notcontains $_ }
if ($libres.Count -lt 3) { throw 'No hay 3 letras de unidad libres.' }
$LP = $libres[0]; $LH = $libres[1]; $LR = $libres[2]
$dp = @(
    "select disk $DiscoUSB", 'clean', 'convert mbr', "uniqueid disk id=$idUsb",
    "create partition primary size=$TamanoWinPEMB", ('format quick fs=fat32 label="{0}-BOOT"' -f $Nombre), 'active', "assign letter=$LP",
    "create partition primary size=$TamanoHerramientasMB", ('format quick fs=ntfs label="{0}-TOOLS"' -f $Nombre), "assign letter=$LH",
    'create partition primary', ('format quick fs=ntfs label="{0}-USB"' -f $Nombre), "assign letter=$LR",
    "uniqueid disk id=$idUsb", 'exit'
)
$dpArchivo = Join-Path $Trabajo 'particionar.txt'
[System.IO.File]::WriteAllLines($dpArchivo, [string[]]$dp, [System.Text.Encoding]::ASCII)
& (Get-RutaSistema 'diskpart.exe') /s $dpArchivo
if ($LASTEXITCODE -ne 0) { throw 'diskpart falló al particionar el USB.' }
Start-Sleep -Seconds 5
foreach ($l in @($LP, $LH, $LR)) { if (-not (Test-Path -LiteralPath "${l}:\")) { throw "No apareció la unidad ${l}: tras particionar." } }
# Storage WMI guarda en caché los datos del disco: se refresca antes de leer la firma
$firmaTxt = ''
for ($intento = 1; $intento -le 5; $intento++) {
    try { Update-HostStorageCache -ErrorAction Stop } catch { }
    $firmaTxt = '{0:X8}' -f [uint32](Get-Disk -Number $DiscoUSB).Signature
    if ($firmaTxt -eq $idUsb) { break }
    Start-Sleep -Seconds 2
}
if ($firmaTxt -ne $idUsb) {
    # Segunda fuente, sin caché: diskpart lee la firma directamente del disco
    $dq = Join-Path $Trabajo 'consultar_id.txt'
    [System.IO.File]::WriteAllLines($dq, [string[]]@("select disk $DiscoUSB", 'uniqueid disk', 'exit'), [System.Text.Encoding]::ASCII)
    $salidaDp = (& (Get-RutaSistema 'diskpart.exe') /s $dq 2>&1 | ForEach-Object { [string]$_ }) -join ' '
    $m = [regex]::Match($salidaDp, '(?i)(?:Id\.? de disco|Disk ID)\s*:\s*([0-9A-F]{8})\b')
    if ($m.Success) { $firmaTxt = $m.Groups[1].Value.ToUpperInvariant() }
    Write-Host ('  diskpart informa la firma: {0}' -f $firmaTxt)
}
if ($firmaTxt -ne $idUsb) { throw ('La firma del USB ({0}) no es la esperada ({1}).' -f $firmaTxt, $idUsb) }
[System.IO.File]::WriteAllText((Join-Path $Trabajo 'usb-id.txt'), $idUsb)
Write-Host "Identidad del USB (firma de disco): $idUsb" -ForegroundColor Green

# ---------------------------------------------------------------------------
Write-Paso '7/9 Escribiendo WinPE en la partición de arranque (MakeWinPEMedia)'
$bootex = ''
if ($CertificadoArranque -eq '2023') { $bootex = '/bootex' }
Assert-Codigo (Invoke-EnAdk ('MakeWinPEMedia /UFD /F "{0}" {1}: {2}' -f $dirWinPE, $LP, $bootex)) 'MakeWinPEMedia'
# MakeWinPEMedia reformatea la partición de arranque: se le vuelve a poner el nombre (FAT32: máx. 11 caracteres)
try { Set-Volume -DriveLetter $LP -NewFileSystemLabel ('{0}-BOOT' -f $Nombre) -ErrorAction Stop } catch { Write-Host '  (no se pudo renombrar la partición de arranque; no afecta el funcionamiento)' -ForegroundColor DarkYellow }
# Referencia de la partición de arranque (se guarda en ESTE PC, fuera del USB)
$nRef = New-Manifiesto -Raiz "${LP}:\" -Salida (Join-Path $Trabajo 'referencia_winpe.sha256')
Write-Host ("Referencia de la partición WINPE guardada ({0} archivos)." -f $nRef)
if ($CertificadoArranque -eq '2023') { Write-Host 'Gestor de arranque firmado con "Windows UEFI CA 2023".' -ForegroundColor Green }
else { Write-Host 'Gestor de arranque firmado con la CA 2011 (equipos antiguos sin la CA 2023).' -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
Write-Paso '8/9 Copiando HERRAMIENTAS y preparando RESPALDO'
& (Get-RutaSistema 'robocopy.exe') $dirStage "${LH}:\" /E /R:1 /W:1 /NP /NFL /NDL | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy falló copiando herramientas (código $LASTEXITCODE)." }
foreach ($c in @('Casos', 'Entrada')) { New-Item -ItemType Directory -Path "${LR}:\$c" -Force | Out-Null }
[System.IO.File]::WriteAllText("${LR}:\RESPALDO.marker", "RESPALDO - USB forense. Aqui se guardan casos, respaldos y cuarentena.`r`n")
$leeme = @(
    'Particion RESPALDO del USB forense.',
    '',
    'Casos\<fecha>\Reporte\reporte.html  -> reporte de cada analisis (abrir en un PC sano).',
    'Casos\<fecha>\Respaldo\              -> archivos recuperados y verificados por hash.',
    'Casos\<fecha>\Cuarentena\            -> archivos sospechosos CIFRADOS (.cuar). No los abra.',
    'Entrada\detecciones_externas.csv     -> (opcional) resultados de Escanear-Con-Defender.ps1.',
    '',
    'ANTES de abrir el respaldo: analicelo con Microsoft Defender actualizado en un PC sano.'
)
[System.IO.File]::WriteAllLines("${LR}:\LEEME.txt", [string[]]$leeme)

if (-not $SinActualizarFirmas) {
    & (Join-Path $PSScriptRoot 'Actualizar-Firmas.ps1') -Trabajo $Trabajo
}

# ---------------------------------------------------------------------------
Write-Paso '9/9 Verificación final'
$verif = Invoke-VerificacionUsb -Trabajo $Trabajo -SinFirmas:$SinActualizarFirmas
if (-not $verif.Ok) {
    $verif.Problemas | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw 'El USB no coincide con la referencia recién creada.'
}
Write-Host 'USB verificado contra la referencia guardada en este PC.' -ForegroundColor Green
if (-not (Test-Path -LiteralPath "${LP}:\EFI\Boot\bootx64.efi")) { throw 'Falta \EFI\Boot\bootx64.efi en la partición WINPE.' }
$txtHuella = @(
    "Huella del ancla del USB forense: $huella",
    ('Creado: {0}   Disco USB: {1} ({2})' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $DiscoUSB, $usb.FriendlyName),
    'Al arrancar el USB, la huella que muestra la pantalla debe ser EXACTAMENTE esta.',
    'Anótela también fuera del PC (papel o el teléfono).',
    "Identidad del USB (firma de disco MBR): $idUsb",
    'Verificación fuerte antes y después de cada uso: Construir\Verificar-USB.ps1'
)
[System.IO.File]::WriteAllLines((Join-Path $Trabajo 'HUELLA-ANCLA.txt'), [string[]]$txtHuella)
Write-Host ''
Write-Host '==============================================================' -ForegroundColor Green
Write-Host ' USB FORENSE CREADO' -ForegroundColor Green
Write-Host (" Huella del ancla: {0}   (ANÓTELA)" -f $huella) -ForegroundColor Green
Write-Host (" WINPE={0}:  HERRAMIENTAS={1}:  RESPALDO={2}:" -f $LP, $LH, $LR) -ForegroundColor Green
Write-Host (" Copia de la huella: {0}" -f (Join-Path $Trabajo 'HUELLA-ANCLA.txt')) -ForegroundColor Green
Write-Host '==============================================================' -ForegroundColor Green
Write-Host 'Expulse el USB de forma segura antes de retirarlo.'
try { Stop-Transcript | Out-Null } catch { }
