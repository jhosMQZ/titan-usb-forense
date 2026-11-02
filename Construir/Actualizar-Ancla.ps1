#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Copia al USB los scripts modificados del kit y vuelve a sellar el ancla
    (manifiesto + Iniciar.ps1 dentro de boot.wim). Úselo SOLO en el PC técnico
    sano, cuando cambien scripts o config.json del kit.

.DESCRIPTION
    1. Identifica el USB por su firma de disco y comprueba que NO fue alterado
       (contra las referencias guardadas en este PC al crearlo).
    2. Sincroniza Herramientas\Scripts (espejo) y los archivos sueltos del kit.
    3. Genera el manifiesto nuevo de HERRAMIENTAS y muestra los cambios.
    4. Copia boot.wim a este PC, lo monta, reemplaza el ancla, lo guarda y lo
       devuelve al USB comprobando su SHA-256.
    5. Nueva referencia de la partición de arranque, nueva huella y verificación
       completa final.
#>
param(
    [string]$Trabajo = 'C:\WinPE_USBForense'
)
$ErrorActionPreference = 'Stop'
$aqui = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
. (Join-Path $aqui 'Manifiesto.ps1')
$repo = Split-Path -Path $aqui -Parent

function Disable-EdicionRapida {
    $firma = @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetStdHandle(int n);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetConsoleMode(IntPtr h, out uint m);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleMode(IntPtr h, uint m);
'@
    try {
        $k = Add-Type -MemberDefinition $firma -Name 'ConsolaAncla' -Namespace 'KitUsb' -PassThru -ErrorAction Stop
        $h = $k::GetStdHandle(-10)
        $m = [uint32]0
        if ($k::GetConsoleMode($h, [ref]$m)) {
            $nuevoModo = ([int64]$m -bor 128) -band [int64]4294967231
            [void]$k::SetConsoleMode($h, [uint32]$nuevoModo)
        }
    } catch { }
}
Disable-EdicionRapida

$logAncla = Join-Path $repo 'actualizar_ancla_log.txt'
try { Start-Transcript -Path $logAncla -Force | Out-Null } catch { }
trap {
    Write-Host ''
    Write-Host ('ERROR: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host ('  en la línea {0}: {1}' -f $_.InvocationInfo.ScriptLineNumber, ([string]$_.InvocationInfo.Line).Trim()) -ForegroundColor Red
    Write-Host 'boot.wim solo se reemplaza al final y tras comprobarlo. Corrija el problema y vuelva a ejecutar ACTUALIZAR-TITAN.bat.' -ForegroundColor Yellow
    Write-Host ('Registro completo: {0}' -f $logAncla) -ForegroundColor Yellow
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

$dism = Get-RutaSistema 'dism.exe'

function Invoke-Dism {
    # Llamada directa (sin Start-Process -Wait, que se cuelga tras montar una imagen)
    param([string[]]$Argumentos)
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $dism @Argumentos 2>&1 | ForEach-Object { Write-Host ('  [DISM] {0}' -f $_) } }
    finally { $ErrorActionPreference = $eap }
    return $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# 1) Identificar el USB y comprobar que está intacto
# ---------------------------------------------------------------------------
Write-Paso 'Buscando el USB por su firma de disco'
$usb = Get-UsbForense -Trabajo $Trabajo
$H = $usb.H; $P = $usb.P
Write-Host ('USB: disco #{0}  firma {1}  WINPE={2}  HERRAMIENTAS={3}  RESPALDO={4}' -f $usb.Disco, $usb.Id, $P, $H, $usb.R) -ForegroundColor Green

Write-Paso 'Comprobando que el USB no fue alterado desde que se creó'
$prev = Invoke-VerificacionUsb -Trabajo $Trabajo -SinFirmas
$reemplazables = @()
if (-not $prev.Ok) {
    # Diferencias en Scripts\ y Blackbox\ (p. ej. una actualización anterior que copió los scripts
    # y no llegó a sellar) se toleran SOLO porque el paso 2 reemplaza esas carpetas enteras con las
    # del kit, y el paso 2b comprueba archivo por archivo que quedaron idénticas. Cualquier otra
    # diferencia (arranque, otras herramientas, archivos ejecutables en RESPALDO...) detiene el proceso.
    $reemplazables = @($prev.Problemas | Where-Object { $_ -match '^HERRAMIENTAS (MODIFICADO|FALTA|SOBRANTE): (Scripts|Blackbox)\\' })
    $otros = @($prev.Problemas | Where-Object { $_ -notmatch '^HERRAMIENTAS (MODIFICADO|FALTA|SOBRANTE): (Scripts|Blackbox)\\' })
    Write-Host 'ATENCIÓN: el USB ya tenía diferencias con la referencia ANTES de este cambio:' -ForegroundColor Yellow
    $prev.Problemas | Select-Object -First 30 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    if ($otros.Count -gt 0) {
        throw 'Hay diferencias fuera de Scripts\ y Blackbox\: re-sellar legitimaría una alteración. Reconstrúyalo con CREAR-USB-TITAN.bat.'
    }
    Write-Host ('Todas están en Scripts\ o Blackbox\ ({0}): se reemplazarán con la versión del kit y se comprobarán una a una.' -f $reemplazables.Count) -ForegroundColor Yellow
} else { Write-Host 'USB intacto.' -ForegroundColor Green }
$viejo = Join-Path $Trabajo 'manifest.sha256'

# ---------------------------------------------------------------------------
# 2) Sincronizar los scripts
# ---------------------------------------------------------------------------
Write-Paso 'Sincronizando los scripts del kit al USB'
& (Get-RutaSistema 'robocopy.exe') (Join-Path $repo 'Herramientas\Scripts') "$H\Scripts" /MIR /R:1 /W:1 /NP /NFL /NDL | Out-Null
if ($LASTEXITCODE -ge 8) { throw ('robocopy falló (código {0}).' -f $LASTEXITCODE) }
# Motor de TITAN BLACKBOX (ejecutable compilado + su código fuente)
if (Test-Path -LiteralPath (Join-Path $repo 'Herramientas\Blackbox\TitanRescate.exe')) {
    & (Get-RutaSistema 'robocopy.exe') (Join-Path $repo 'Herramientas\Blackbox') "$H\Blackbox" /MIR /R:1 /W:1 /NP /NFL /NDL | Out-Null
    if ($LASTEXITCODE -ge 8) { throw ('robocopy falló copiando el motor BLACKBOX (código {0}).' -f $LASTEXITCODE) }
} else { Write-Host 'AVISO: falta Herramientas\Blackbox\TitanRescate.exe (compílelo con Construir\Compilar-Rescate.ps1).' -ForegroundColor Yellow }
foreach ($f in @('INICIAR.bat', 'USB-FORENSE.marker', 'ClamAV\freshclam.conf', 'ClamAV\LEEME.txt', 'Smartmontools\LEEME.txt')) {
    $origen = Join-Path $repo ('Herramientas\' + $f)
    if (Test-Path -LiteralPath $origen) { Copy-Item -LiteralPath $origen -Destination ('{0}\{1}' -f $H, $f) -Force }
}

# 2b) Comprobación: Scripts\ y Blackbox\ del USB idénticos al kit, archivo por archivo
Write-Paso 'Comprobando que los scripts y el motor del USB son idénticos a los del kit'
$distintos = [System.Collections.Generic.List[string]]::new()
foreach ($par in @(@('Herramientas\Scripts', 'Scripts'), @('Herramientas\Blackbox', 'Blackbox'))) {
    $dirKit = Join-Path $repo $par[0]
    $dirUsb = Join-Path $H $par[1]
    if (-not (Test-Path -LiteralPath $dirKit)) { continue }
    $kit = @{}
    foreach ($f in (Get-ChildItem -LiteralPath $dirKit -Recurse -File)) { $kit[$f.FullName.Substring($dirKit.Length).ToLowerInvariant()] = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash }
    $vistos = @{}
    foreach ($f in (Get-ChildItem -LiteralPath $dirUsb -Recurse -File)) {
        $rel = $f.FullName.Substring($dirUsb.Length).ToLowerInvariant()
        $vistos[$rel] = $true
        if (-not $kit.ContainsKey($rel)) { $distintos.Add(('{0}{1} (no está en el kit)' -f $par[1], $rel)) }
        elseif ($kit[$rel] -ne (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash) { $distintos.Add(('{0}{1} (contenido distinto)' -f $par[1], $rel)) }
    }
    foreach ($k in $kit.Keys) { if (-not $vistos.ContainsKey($k)) { $distintos.Add(('{0}{1} (falta en el USB)' -f $par[1], $k)) } }
}
if ($distintos.Count -gt 0) {
    $distintos | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw 'Los scripts del USB no quedaron idénticos a los del kit: no se sella.'
}
Write-Host 'Scripts y motor del USB idénticos al kit.' -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3) Nuevo manifiesto
# ---------------------------------------------------------------------------
Write-Paso 'Generando el nuevo manifiesto de HERRAMIENTAS'
$nuevo = Join-Path $Trabajo 'manifest.nuevo.sha256'
$nArch = New-Manifiesto -Raiz ('{0}\' -f $H) -Salida $nuevo
Write-Host ('{0} archivos en el manifiesto.' -f $nArch)
if (Test-Path -LiteralPath $viejo) {
    $a = @(Get-Content -LiteralPath $viejo); $b = @(Get-Content -LiteralPath $nuevo)
    $dif = @(Compare-Object -ReferenceObject $a -DifferenceObject $b)
    Write-Host ('Cambios ({0} líneas; + nuevo / - anterior):' -f $dif.Count)
    foreach ($d in $dif) {
        $marca = '+'; if ($d.SideIndicator -eq '<=') { $marca = '-' }
        Write-Host ('  {0} {1}' -f $marca, $d.InputObject.Substring(66))
    }
}
$resp = ([string](Read-Host 'Revise los cambios. Escriba SI para sellar el nuevo ancla')).Trim().ToUpperInvariant()
if ($resp -ne 'SI' -and $resp -ne 'SÍ') { throw 'Cancelado por el usuario. (Los scripts copiados no se usarán: el ancla vieja los rechazará hasta sellar.)' }

# ---------------------------------------------------------------------------
# 4) Actualizar boot.wim (trabajando sobre una copia en este PC)
# ---------------------------------------------------------------------------
Write-Paso 'Preparando boot.wim'
$mnt = Join-Path $Trabajo 'mount_ancla'
$wimLocal = Join-Path $Trabajo 'boot_ancla.wim'
$wimUsb = '{0}\sources\boot.wim' -f $P
# Restos de un intento anterior
if ((Test-Path -LiteralPath $mnt) -and @(Get-ChildItem -LiteralPath $mnt -Force -ErrorAction SilentlyContinue).Count -gt 0) {
    Write-Host 'Desmontando un montaje anterior que quedó abierto...' -ForegroundColor Yellow
    [void](Invoke-Dism @('/Unmount-Image', ('/MountDir:{0}' -f $mnt), '/Discard'))
}
[void](Invoke-Dism @('/Cleanup-Mountpoints'))
New-Item -ItemType Directory -Path $mnt -Force | Out-Null
Copy-Item -LiteralPath $wimUsb -Destination $wimLocal -Force
Set-ItemProperty -LiteralPath $wimLocal -Name IsReadOnly -Value $false

Write-Paso 'Montando boot.wim (tarda 1-3 minutos)'
if ((Invoke-Dism @('/Mount-Image', ('/ImageFile:{0}' -f $wimLocal), '/Index:1', ('/MountDir:{0}' -f $mnt))) -ne 0) { throw 'No se pudo montar boot.wim.' }
$ok = $false
try {
    New-Item -ItemType Directory -Path "$mnt\Ancla" -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $repo 'Ancla\Iniciar.ps1') -Destination "$mnt\Ancla\Iniciar.ps1" -Force
    Copy-Item -LiteralPath $nuevo -Destination "$mnt\Ancla\manifest.sha256" -Force
    Copy-Item -LiteralPath (Join-Path $repo 'Ancla\startnet.cmd') -Destination "$mnt\Windows\System32\startnet.cmd" -Force
    Copy-Item -LiteralPath (Join-Path $repo 'Ancla\unattend.xml') -Destination "$mnt\Ancla\unattend.xml" -Force
    [System.IO.File]::WriteAllText("$mnt\Ancla\usb-id.txt", $usb.Id)
    # Comprobación antes de guardar
    foreach ($par in @(@('Ancla\Iniciar.ps1', "$mnt\Ancla\Iniciar.ps1"), @('Ancla\startnet.cmd', "$mnt\Windows\System32\startnet.cmd"))) {
        if ((Get-HashSha256Archivo (Join-Path $repo $par[0])) -ne (Get-HashSha256Archivo $par[1])) { throw ('La copia de {0} dentro de boot.wim no coincide.' -f $par[0]) }
    }
    if ((Get-HashSha256Archivo $nuevo) -ne (Get-HashSha256Archivo "$mnt\Ancla\manifest.sha256")) { throw 'La copia del manifiesto dentro de boot.wim no coincide.' }
    Write-Paso 'Guardando boot.wim'
    if ((Invoke-Dism @('/Unmount-Image', ('/MountDir:{0}' -f $mnt), '/Commit')) -ne 0) { throw 'No se pudo guardar boot.wim.' }
    $ok = $true
} finally {
    if (-not $ok) { [void](Invoke-Dism @('/Unmount-Image', ('/MountDir:{0}' -f $mnt), '/Discard')) }
}

Write-Paso 'Copiando el boot.wim nuevo al USB'
$hashLocal = Get-HashSha256Archivo $wimLocal
$wimTmp = '{0}\sources\boot.wim.nuevo' -f $P
Copy-Item -LiteralPath $wimLocal -Destination $wimTmp -Force
if ((Get-HashSha256Archivo $wimTmp) -ne $hashLocal) { Remove-Item -LiteralPath $wimTmp -Force; throw 'La copia de boot.wim al USB salió dañada. El USB no se modificó (pruebe otro puerto).' }
Set-ItemProperty -LiteralPath $wimUsb -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
Move-Item -LiteralPath $wimTmp -Destination $wimUsb -Force
if ((Get-HashSha256Archivo $wimUsb) -ne $hashLocal) { throw 'boot.wim en el USB no coincide tras reemplazarlo. Vuelva a ejecutar este actualizador.' }
Remove-Item -LiteralPath $wimLocal -Force -ErrorAction SilentlyContinue
Write-Host 'boot.wim reemplazado y comprobado.' -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5) Referencias nuevas, huella y verificación completa
# ---------------------------------------------------------------------------
Move-Item -LiteralPath $nuevo -Destination $viejo -Force
[void](New-Manifiesto -Raiz ('{0}\' -f $P) -Salida (Join-Path $Trabajo 'referencia_winpe.sha256'))
$huella = Get-HuellaManifiesto $viejo
[System.IO.File]::WriteAllLines((Join-Path $Trabajo 'HUELLA-ANCLA.txt'), [string[]]@("Huella del ancla del USB forense: $huella", ('Actualizada: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'))))

Write-Paso 'Verificación completa final'
$fin = Invoke-VerificacionUsb -Trabajo $Trabajo
foreach ($x in $fin.Avisos) { Write-Host ('  AVISO: {0}' -f $x) -ForegroundColor Yellow }
if (-not $fin.Ok) {
    $fin.Problemas | Select-Object -First 30 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw 'La verificación final encontró problemas (ver arriba).'
}
Write-Host ''
Write-Host '=================================================================' -ForegroundColor Green
Write-Host ('  ANCLA ACTUALIZADA.  NUEVA HUELLA:  {0}' -f $huella) -ForegroundColor Green
Write-Host '  Anótela: la verá en pantalla cada vez que arranque el USB.' -ForegroundColor Green
Write-Host '=================================================================' -ForegroundColor Green
try { Stop-Transcript | Out-Null } catch { }
