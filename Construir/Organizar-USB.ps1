<#
.SYNOPSIS
    Reorganiza todo el contenido de una memoria USB dentro de UNA sola carpeta,
    le cambia el nombre (etiqueta) y la prueba. No borra ningún archivo tuyo.

.DESCRIPTION
    1. Comprueba que la unidad es extraíble/USB y no el disco del sistema.
    2. Inventario SHA-256 de todos los archivos ANTES.
    3. Revisa señales de virus de USB (autorun.inf, accesos directos en la raíz,
       carpetas ocultas de sistema). Solo informa.
    4. Mueve cada elemento de la raíz a la carpeta destino (en la misma unidad
       mover = renombrar: rápido y sin copiar datos). Guarda un registro para deshacer.
    5. Inventario DESPUÉS y comparación archivo por archivo (ruta y SHA-256).
    6. Cambia la etiqueta del volumen y la vuelve a leer.
    7. Pruebas: salud del volumen, chkdsk SIN reparar y prueba de escritura y
       lectura con un archivo temporal propio que luego se elimina.
    8. Reporte en la carpeta del kit.

    -Deshacer: devuelve todo a su sitio usando el registro del último movimiento.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Organizar-USB.ps1 -Letra E -Carpeta ARCHIVOS -Etiqueta TITAN-USB
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z]$')][string]$Letra,
    [ValidatePattern('^[^\\/:*?"<>|]+$')][string]$Carpeta = 'ARCHIVOS',
    [string]$Etiqueta = 'TITAN-USB',
    [string]$CarpetaReporte = '',
    [switch]$Deshacer
)
$ErrorActionPreference = 'Stop'
# En Windows PowerShell 5.1 $PSScriptRoot no existe en los valores por defecto de param()
$baseScript = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
if (-not $CarpetaReporte) { $CarpetaReporte = Split-Path -Path $baseScript -Parent }
$Letra = $Letra.ToUpperInvariant()
$raiz = '{0}:\' -f $Letra
$destino = Join-Path $raiz $Carpeta
$sistema = @('System Volume Information', '$RECYCLE.BIN', 'RECYCLER')
$registroMov = Join-Path $CarpetaReporte ('movimientos_usb_{0}.csv' -f $Letra)
$reporte = Join-Path $CarpetaReporte 'organizar_usb_reporte.txt'
$lineas = New-Object System.Collections.Generic.List[string]
$utf8 = New-Object System.Text.UTF8Encoding($true)

function Write-Paso {
    param([string]$T, [string]$Color = 'Cyan')
    Write-Host $T -ForegroundColor $Color
    $lineas.Add($T)
}

function Get-Inventario {
    # Lista de archivos (ruta relativa a $Base -> SHA-256), sin carpetas de sistema
    param([string]$Base)
    $res = @{}
    $baseN = $Base.TrimEnd('\') + '\'
    # Primer nivel por separado: así nunca se entra en "System Volume Information" (acceso denegado)
    $todos = New-Object System.Collections.Generic.List[object]
    foreach ($it in @(Get-ChildItem -LiteralPath $baseN -Force -ErrorAction Stop)) {
        if ($sistema -contains $it.Name) { continue }
        if ($it.PSIsContainer) {
            foreach ($f in @(Get-ChildItem -LiteralPath $it.FullName -Recurse -Force -File -ErrorAction Stop)) { $todos.Add($f) }
        } else { $todos.Add($it) }
    }
    foreach ($f in $todos) {
        $rel = $f.FullName.Substring($baseN.Length)
        $res[$rel] = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
    }
    return $res
}

function Save-Reporte {
    [System.IO.File]::WriteAllLines($reporte, [string[]]$lineas, $utf8)
    Write-Host ''
    Write-Host ("Reporte: {0}" -f $reporte) -ForegroundColor Green
}

# Registro completo de la consola (para diagnosticar cualquier fallo)
$consola = Join-Path $CarpetaReporte 'organizar_usb_consola.txt'
try { Start-Transcript -Path $consola -Force | Out-Null } catch { }

# Cualquier error que detenga el script queda escrito en el reporte, con su línea
trap {
    $msg = $_.Exception.Message
    $lin = $_.InvocationInfo.ScriptLineNumber
    $cmd = ''
    if ($_.InvocationInfo.Line) { $cmd = $_.InvocationInfo.Line.Trim() }
    Write-Paso ''
    Write-Paso ('ERROR: {0}' -f $msg) 'Red'
    Write-Paso ('  en la línea {0}: {1}' -f $lin, $cmd) 'Red'
    Write-Paso 'No se borró ningún archivo. Si alguno se alcanzó a mover, el registro de movimientos permite deshacerlo.' 'Yellow'
    Save-Reporte
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

# ---------------------------------------------------------------------------
# 1) Comprobaciones de seguridad
# ---------------------------------------------------------------------------
Write-Paso ('ORGANIZAR USB  -  {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'))
if (-not (Test-Path -LiteralPath $raiz)) { throw "La unidad $raiz no existe." }
if ($Letra -eq $env:SystemDrive.Substring(0, 1).ToUpperInvariant()) { throw 'Protección: esa es la unidad del sistema.' }
$di = New-Object System.IO.DriveInfo -ArgumentList $Letra
$esUsb = $false
try {
    $disco = Get-Partition -DriveLetter $Letra -ErrorAction Stop | Get-Disk -ErrorAction Stop
    $esUsb = ([string]$disco.BusType -eq 'USB') -and -not $disco.IsSystem -and -not $disco.IsBoot
    Write-Paso ('Disco: {0}  bus={1}  {2:N1} GB' -f $disco.FriendlyName, $disco.BusType, ($disco.Size / 1GB))
} catch { }
if (-not $esUsb -and [string]$di.DriveType -ne 'Removable') { throw "Protección: $raiz no es una memoria USB/extraíble." }
$vol = Get-Volume -DriveLetter $Letra
Write-Paso ('Volumen {0}  sistema de archivos={1}  etiqueta actual="{2}"  libre={3:N1} GB de {4:N1} GB' -f $raiz, $vol.FileSystem, $vol.FileSystemLabel, ($vol.SizeRemaining / 1GB), ($vol.Size / 1GB))

# ---------------------------------------------------------------------------
# Modo deshacer
# ---------------------------------------------------------------------------
if ($Deshacer) {
    if (-not (Test-Path -LiteralPath $registroMov)) { throw "No existe el registro $registroMov" }
    $antes = Get-Inventario -Base $raiz
    $n = 0
    foreach ($m in @(Import-Csv -LiteralPath $registroMov -Encoding UTF8)) {
        if ((Test-Path -LiteralPath $m.Nuevo) -and -not (Test-Path -LiteralPath $m.Original)) {
            Move-Item -LiteralPath $m.Nuevo -Destination $m.Original
            Write-Paso ("Devuelto: {0}" -f $m.Original) 'Gray'
            $n++
        }
    }
    if ((Test-Path -LiteralPath $destino) -and @(Get-ChildItem -LiteralPath $destino -Force).Count -eq 0) { Remove-Item -LiteralPath $destino -Force }
    $despues = Get-Inventario -Base $raiz
    $vals1 = @($antes.Values | Sort-Object); $vals2 = @($despues.Values | Sort-Object)
    $iguales = ($vals1.Count -eq $vals2.Count) -and (@(Compare-Object $vals1 $vals2).Count -eq 0)
    Write-Paso ("Elementos devueltos: {0}. Contenido idéntico (hashes): {1}" -f $n, $iguales) $(if ($iguales) { 'Green' } else { 'Red' })
    Save-Reporte
    try { Stop-Transcript | Out-Null } catch { }
    exit 0
}

# ---------------------------------------------------------------------------
# 2) Inventario ANTES
# ---------------------------------------------------------------------------
Write-Paso ''
Write-Paso 'Inventario SHA-256 antes de mover...'
$antes = Get-Inventario -Base $raiz
$bytes = 0
foreach ($k in $antes.Keys) { $bytes += (Get-Item -LiteralPath (Join-Path $raiz $k) -Force).Length }
Write-Paso ('{0} archivos, {1:N1} MB' -f $antes.Count, ($bytes / 1MB))

# ---------------------------------------------------------------------------
# 3) Señales de virus de USB (solo informa)
# ---------------------------------------------------------------------------
$alertas = @()
foreach ($it in @(Get-ChildItem -LiteralPath $raiz -Force)) {
    if ($sistema -contains $it.Name) { continue }
    if ($it.Name -ieq 'autorun.inf') { $alertas += 'autorun.inf en la raíz' }
    if ($it.Extension -ieq '.lnk') { $alertas += ('Acceso directo en la raíz: ' + $it.Name) }
    $oculto = ($it.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
    $sis = ($it.Attributes -band [System.IO.FileAttributes]::System) -ne 0
    if ($oculto -and $sis) { $alertas += ('Elemento oculto + sistema en la raíz: ' + $it.Name) }
}
$archivosRaiz = New-Object System.Collections.Generic.List[object]
foreach ($it in @(Get-ChildItem -LiteralPath $raiz -Force)) {
    if ($sistema -contains $it.Name) { continue }
    if ($it.PSIsContainer) { foreach ($x in @(Get-ChildItem -LiteralPath $it.FullName -Recurse -Force -File -ErrorAction SilentlyContinue)) { $archivosRaiz.Add($x) } }
    else { $archivosRaiz.Add($it) }
}
foreach ($f in $archivosRaiz) {
    if ($f.Extension -match '^\.(exe|scr|vbs|vbe|js|jse|wsf|hta|bat|cmd|pif|com)$') { $alertas += ('Ejecutable/script: ' + $f.FullName.Substring(3)) }
}
if ($alertas.Count -eq 0) { Write-Paso 'Señales de virus de USB: ninguna.' 'Green' }
else {
    Write-Paso 'ATENCIÓN - posibles señales de virus de USB (no se tocan, revíselas):' 'Yellow'
    foreach ($a in $alertas) { Write-Paso ('  ' + $a) 'Yellow' }
}

# ---------------------------------------------------------------------------
# 4) Mover todo a la carpeta destino
# ---------------------------------------------------------------------------
Write-Paso ''
Write-Paso ("Moviendo todo a {0} ..." -f $destino)
$items = @(Get-ChildItem -LiteralPath $raiz -Force | Where-Object { ($sistema -notcontains $_.Name) -and ($_.Name -ine $Carpeta) })
foreach ($it in $items) {
    if (Test-Path -LiteralPath (Join-Path $destino $it.Name)) { throw ("Ya existe {0} dentro de {1}: no se sobrescribe nada. Revise y repita." -f $it.Name, $Carpeta) }
}
if (-not (Test-Path -LiteralPath $destino)) { New-Item -ItemType Directory -Path $destino | Out-Null }
$mov = New-Object System.Collections.Generic.List[object]
if (Test-Path -LiteralPath $registroMov) { foreach ($m in @(Import-Csv -LiteralPath $registroMov -Encoding UTF8)) { $mov.Add($m) } }
try {
    foreach ($it in $items) {
        $nuevo = Join-Path $destino $it.Name
        Move-Item -LiteralPath $it.FullName -Destination $nuevo
        $mov.Add([pscustomobject]@{ Original = $it.FullName; Nuevo = $nuevo; Fecha = (Get-Date -Format 's') })
        Write-Paso ("  {0}  ->  {1}\{0}" -f $it.Name, $Carpeta) 'Gray'
    }
} finally {
    # El registro se guarda siempre, incluso si algo falló a mitad (para poder deshacer)
    $mov | Export-Csv -LiteralPath $registroMov -NoTypeInformation -Encoding UTF8
}

# ---------------------------------------------------------------------------
# 5) Inventario DESPUÉS y comparación
# ---------------------------------------------------------------------------
Write-Paso ''
Write-Paso 'Verificando que no se perdió ni cambió nada...'
$despues = Get-Inventario -Base $destino
$faltan = @(); $distintos = @()
foreach ($k in $antes.Keys) {
    $k2 = $k
    if ($k.StartsWith($Carpeta + '\', [System.StringComparison]::OrdinalIgnoreCase)) { $k2 = $k.Substring($Carpeta.Length + 1) }
    if (-not $despues.ContainsKey($k2)) { $faltan += $k; continue }
    if ($despues[$k2] -ne $antes[$k]) { $distintos += $k }
}
$sobrantes = $despues.Count - ($antes.Count - $faltan.Count)
$verifOk = ($faltan.Count -eq 0 -and $distintos.Count -eq 0 -and $despues.Count -eq $antes.Count)
$colorV = 'Red'; if ($verifOk) { $colorV = 'Green' }
Write-Paso ('Antes: {0} archivos | Después: {1} | Faltan: {2} | Distintos: {3} | Extra: {4}  =>  {5}' -f $antes.Count, $despues.Count, $faltan.Count, $distintos.Count, $sobrantes, $(if ($verifOk) { 'CORRECTO' } else { 'REVISAR' })) $colorV
foreach ($x in $faltan) { Write-Paso ('  FALTA: ' + $x) 'Red' }
foreach ($x in $distintos) { Write-Paso ('  DISTINTO: ' + $x) 'Red' }

# ---------------------------------------------------------------------------
# 6) Etiqueta
# ---------------------------------------------------------------------------
Write-Paso ''
$max = 32
if (@('FAT32', 'FAT', 'exFAT') -contains [string]$vol.FileSystem) { $max = 11 }
$etq = $Etiqueta.Trim()
if ($etq.Length -gt $max) { $etq = $etq.Substring(0, $max); Write-Paso ("La etiqueta se recorta a {0} caracteres ({1}): {2}" -f $max, $vol.FileSystem, $etq) 'Yellow' }
$etiquetaOk = $false
try {
    Set-Volume -DriveLetter $Letra -NewFileSystemLabel $etq -ErrorAction Stop
} catch {
    & (Join-Path $env:SystemRoot 'System32\label.exe') ('{0}:' -f $Letra) $etq | Out-Null
}
$leida = (Get-Volume -DriveLetter $Letra).FileSystemLabel
if ($leida -eq $etq) { $etiquetaOk = $true }
$colorE = 'Red'; if ($etiquetaOk) { $colorE = 'Green' }
Write-Paso ('Etiqueta: "{0}" -> "{1}" (leída: "{2}")  =>  {3}' -f $vol.FileSystemLabel, $etq, $leida, $(if ($etiquetaOk) { 'CORRECTO' } else { 'FALLÓ' })) $colorE

# ---------------------------------------------------------------------------
# 7) Pruebas de la memoria
# ---------------------------------------------------------------------------
Write-Paso ''
Write-Paso 'Pruebas de la memoria:'
$v2 = Get-Volume -DriveLetter $Letra
Write-Paso ('  Salud del volumen: {0} / {1}' -f $v2.HealthStatus, $v2.OperationalStatus) $(if ([string]$v2.HealthStatus -eq 'Healthy') { 'Green' } else { 'Yellow' })

$chk = & (Join-Path $env:SystemRoot 'System32\chkdsk.exe') ('{0}:' -f $Letra) 2>&1 | ForEach-Object { [string]$_ }
$codChk = $LASTEXITCODE
$txtChk = "código $codChk"
if ($codChk -eq 0) { $txtChk = 'sin errores' }
elseif ($codChk -eq 1) { $txtChk = 'errores corregidos' }
elseif ($codChk -eq 2) { $txtChk = 'limpieza menor sugerida' }
elseif ($codChk -eq 3) { $txtChk = 'ERRORES encontrados (sin reparar)' }
Write-Paso ('  chkdsk (solo lectura, sin reparar): {0}' -f $txtChk) $(if ($codChk -eq 0) { 'Green' } else { 'Yellow' })
$chkResumen = @($chk | Where-Object { $_ -match '(?i)(error|corrupt|dañ|problem|bad|defectuos|sin problemas|no problems|found no)' } | Select-Object -First 5)
foreach ($c in $chkResumen) { Write-Paso ('     ' + $c.Trim()) 'Gray' }

$rwOk = $false
$prueba = Join-Path $raiz ('.prueba_lectura_escritura_{0}.tmp' -f (Get-Random))
try {
    $tam = 32MB
    $datos = New-Object byte[] $tam
    (New-Object System.Random).NextBytes($datos)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h1 = [System.BitConverter]::ToString($sha.ComputeHash($datos))
    $t0 = Get-Date
    $fs = New-Object System.IO.FileStream -ArgumentList $prueba, ([System.IO.FileMode]::CreateNew), ([System.IO.FileAccess]::Write), ([System.IO.FileShare]::None), 1048576, ([System.IO.FileOptions]::WriteThrough)
    try { $fs.Write($datos, 0, $datos.Length); $fs.Flush($true) } finally { $fs.Dispose() }
    $seg1 = ((Get-Date) - $t0).TotalSeconds
    $t1 = Get-Date
    $leidos = [System.IO.File]::ReadAllBytes($prueba)
    $seg2 = ((Get-Date) - $t1).TotalSeconds
    $h2 = [System.BitConverter]::ToString($sha.ComputeHash($leidos))
    $sha.Dispose()
    $rwOk = ($h1 -eq $h2)
    $velW = 32 / [Math]::Max($seg1, 0.001); $velR = 32 / [Math]::Max($seg2, 0.001)
    Write-Paso ('  Escritura/lectura de 32 MB: {0}  (escritura ~{1:N1} MB/s, lectura ~{2:N0} MB/s)' -f $(if ($rwOk) { 'datos idénticos' } else { 'DATOS DISTINTOS: memoria defectuosa' }), $velW, $velR) $(if ($rwOk) { 'Green' } else { 'Red' })
    Write-Paso '  (la lectura puede salir de la caché de Windows; la cifra de escritura es la representativa)' 'Gray'
} catch {
    Write-Paso ('  Prueba de escritura/lectura falló: {0}' -f $_.Exception.Message) 'Red'
} finally {
    # Archivo de prueba creado por este script, no es tuyo
    if (Test-Path -LiteralPath $prueba) { Remove-Item -LiteralPath $prueba -Force -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------------------
# 8) Resumen
# ---------------------------------------------------------------------------
Write-Paso ''
$todoOk = $verifOk -and $etiquetaOk -and $rwOk -and ($codChk -eq 0 -or $codChk -eq 2)
if ($todoOk) { Write-Paso 'RESULTADO: TODO CORRECTO' 'Green' } else { Write-Paso 'RESULTADO: HAY PUNTOS PARA REVISAR (ver arriba)' 'Yellow' }
Write-Paso ('Registro para deshacer: {0}' -f $registroMov) 'Gray'
Write-Paso ('Para deshacer: powershell -NoProfile -ExecutionPolicy Bypass -File "{0}" -Letra {1} -Carpeta "{2}" -Deshacer' -f $MyInvocation.MyCommand.Path, $Letra, $Carpeta) 'Gray'
Save-Reporte
try { Stop-Transcript | Out-Null } catch { }
