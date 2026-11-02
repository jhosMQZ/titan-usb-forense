<#
.SYNOPSIS
    Punto de entrada de confianza. Vive DENTRO de boot.wim (X:\Ancla), junto
    con la copia "ancla" del manifiesto de hashes y la identidad del USB.

.DESCRIPTION
    Al arrancar WinPE:
      1. Identifica el USB de trabajo por su FIRMA DE DISCO única (sellada en
         X:\Ancla\usb-id.txt al crearlo), no por archivos marcadores que un
         atacante podría plantar en el disco analizado.
      2. Todo disco que no sea ese USB queda FUERA DE LÍNEA y en SOLO LECTURA.
         Nunca se quita la protección de solo lectura a otro disco.
      3. Verifica la integridad de HERRAMIENTAS contra el manifiesto ancla
         (cada archivo, faltantes y sobrantes) y las bases .cvd de ClamAV.
      4. Si el CÓDIGO no es íntegro, NO permite analizar (sin anulación manual).
      5. Copia los scripts verificados a la RAM (X:), los vuelve a comprobar y
         los ejecuta desde ahí.

    -SoloVerificar: hace solo el paso 3.
       Código de salida: 0 = correcto, 2 = código correcto pero avisos en las
       bases de firmas, 1 = fallo de integridad del código.
#>
param(
    [switch]$SoloVerificar,
    [string]$Herramientas
)
$ErrorActionPreference = 'Stop'
$Ancla = $PSScriptRoot
$ArchivoManifiesto = Join-Path $Ancla 'manifest.sha256'
$ArchivoIdUsb = Join-Path $Ancla 'usb-id.txt'
$MarcadorHerramientas = 'USB-FORENSE.marker'
$MarcadorRespaldo = 'RESPALDO.marker'

function Get-HashSha256 {
    param([string]$Ruta)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Ruta)
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '') }
    finally { $fs.Dispose(); $sha.Dispose() }
}

function Get-Huella {
    if (-not (Test-Path -LiteralPath $ArchivoManifiesto)) { return '(sin manifiesto)' }
    $h = Get-HashSha256 $ArchivoManifiesto
    return ('{0}-{1}-{2}-{3}' -f $h.Substring(0, 4), $h.Substring(4, 4), $h.Substring(8, 4), $h.Substring(12, 4))
}

function Get-IdUsbEsperado {
    if (-not (Test-Path -LiteralPath $ArchivoIdUsb)) { return $null }
    $t = ([System.IO.File]::ReadAllText($ArchivoIdUsb)).Trim()
    if ($t -notmatch '^[0-9A-Fa-f]{8}$') { return $null }
    return [Convert]::ToUInt32($t, 16)
}

function Test-ExcluidoDeVerificacion {
    param([string]$Relativa)
    return ($Relativa -match '(?i)^(System Volume Information|\$RECYCLE\.BIN)\\' -or $Relativa -match '(?i)^ClamAV\\database\\')
}

function Get-ArchivosVerificables {
    # Recorrido que salta las carpetas excluidas y no aborta por una carpeta sin acceso
    param([string]$Raiz, $Avisos)
    $pila = [System.Collections.Generic.Stack[string]]::new()
    $pila.Push($Raiz)
    while ($pila.Count -gt 0) {
        $dir = $pila.Pop()
        $rel = ''
        if ($dir.Length -gt $Raiz.Length) { $rel = $dir.Substring($Raiz.Length).TrimEnd('\') + '\' }
        if ($rel -and (Test-ExcluidoDeVerificacion $rel)) { continue }
        try {
            foreach ($f in [System.IO.Directory]::GetFiles($dir)) { $f }
            foreach ($d in [System.IO.Directory]::GetDirectories($dir)) {
                if (([System.IO.File]::GetAttributes($d) -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $pila.Push($d) }
                else { $Avisos.Add("Enlace/unión inesperado (no se sigue): $d") }
            }
        } catch { $Avisos.Add(('Sin acceso a {0}: {1}' -f $dir, $_.Exception.Message)) }
    }
}

# ---------------------------------------------------------------------------
# Discos vía DISKPART. En algunos WinPE (visto en un portátil con NVMe) los
# cmdlets de almacenamiento (Get-Disk, Get-Partition) devuelven listas vacías;
# diskpart funciona siempre, así que es la fuente principal.
# ---------------------------------------------------------------------------
function Invoke-Diskpart {
    param([string[]]$Comandos)
    $archivo = Join-Path $env:TEMP ('dp_{0}.txt' -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllLines($archivo, [string[]]($Comandos + @('exit')), [System.Text.Encoding]::ASCII)
    $salida = @()
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $salida = @(& (Join-Path $env:SystemRoot 'System32\diskpart.exe') /s $archivo 2>&1 | ForEach-Object { [string]$_ })
    } finally {
        $ErrorActionPreference = $eap
        Remove-Item -LiteralPath $archivo -Force -ErrorAction SilentlyContinue
    }
    return , $salida
}

function ConvertFrom-TamanoDiskpart {
    # "476 GB" -> bytes aproximados
    param([string]$Texto)
    $m = [regex]::Match([string]$Texto, '(\d+)\s*(B|KB|MB|GB|TB)\b', 'IgnoreCase')
    if (-not $m.Success) { return [int64]0 }
    $n = [int64]$m.Groups[1].Value
    switch ($m.Groups[2].Value.ToUpperInvariant()) {
        'KB' { return $n * 1KB }
        'MB' { return $n * 1MB }
        'GB' { return $n * 1GB }
        'TB' { return $n * 1TB }
    }
    return $n
}

function Get-ListaDiscosDp {
    $res = @()
    foreach ($l in (Invoke-Diskpart @('list disk'))) {
        $m = [regex]::Match($l, '^\s*\*?\s*(?:Disk|Disco)\s+(\d+)\s+(.+?)\s{2,}(\d+\s*[KMGT]?B)\b')
        if ($m.Success) {
            $res += [pscustomobject]@{ Number = [int]$m.Groups[1].Value; Estado = $m.Groups[2].Value.Trim(); Tamano = $m.Groups[3].Value }
        }
    }
    return $res
}

function Get-ColumnaDp {
    # Texto de una columna de la salida de diskpart (por posición)
    param([string]$Linea, [int]$Inicio, [int]$Largo)
    if ($Inicio -lt 0 -or $Inicio -ge $Linea.Length) { return '' }
    $fin = [Math]::Min($Linea.Length, $Inicio + $Largo)
    return $Linea.Substring($Inicio, $fin - $Inicio).Trim()
}

function Get-DetalleDiscoDp {
    <#
      Devuelve: Number, FriendlyName, BusType, Id (firma MBR de 8 hex o {GUID}),
      PartitionStyle, Size, IsOffline, IsReadOnly, IsBoot, Volumenes (Num, Letra,
      Fs, Tamano, Info).
    #>
    param([int]$Numero, [string]$TamanoTexto = '')
    $o = Invoke-Diskpart @("select disk $Numero", 'detail disk', 'uniqueid disk')
    $d = [ordered]@{
        Number = $Numero; FriendlyName = ''; BusType = ''; Id = ''; PartitionStyle = ''
        Size = (ConvertFrom-TamanoDiskpart $TamanoTexto); IsOffline = $false; IsReadOnly = $false; IsBoot = $false
        Volumenes = @()
    }
    $iId = -1
    for ($i = 0; $i -lt $o.Count; $i++) {
        $l = $o[$i]
        if ($iId -lt 0 -and $l -match '^\s*(?:Disk ID|Id\.? de disco|Id\.? del disco)\s*:\s*(\S+)') { $iId = $i; $d.Id = $Matches[1].Trim('{', '}').ToUpperInvariant(); continue }
        if ($l -match '^\s*(?:Type|Tipo)\s*:\s*(.+?)\s*$') { if (-not $d.BusType) { $d.BusType = $Matches[1] }; continue }
        if ($l -match '^\s*(?:Status|Estado)\s*:\s*(.+?)\s*$') { if ($Matches[1] -match '(?i)offline|sin conexi|no conectado|fuera de l') { $d.IsOffline = $true }; continue }
        if ($l -match '^\s*(?:Current Read-only State|Estado actual de solo lectura|Estado de solo lectura actual)\s*:\s*(\S+)') { $d.IsReadOnly = ($Matches[1] -match '(?i)^(yes|s)'); continue }
        if ($l -match '^\s*(?:Boot Disk|Disco de arranque)\s*:\s*(\S+)') { $d.IsBoot = ($Matches[1] -match '(?i)^(yes|s)'); continue }
    }
    if ($iId -gt 0) {
        for ($j = $iId - 1; $j -ge 0; $j--) {
            $t = $o[$j].Trim()
            if ($t -and $t -notmatch '(?i)(selected|seleccionado|^Microsoft DiskPart|^DISKPART>|Copyright|^On computer|^En el equipo|^Leaving|^Saliendo)') { $d.FriendlyName = $t; break }
        }
    }
    if ($d.Id -match '^[0-9A-F]{8}$') { $d.PartitionStyle = 'MBR' } elseif ($d.Id) { $d.PartitionStyle = 'GPT' }
    # Volúmenes: columnas según la cabecera ("Ltr", "Fs", "Size"/"Tamaño", "Info")
    $cab = $null
    foreach ($l in $o) { if ($l -match 'Ltr' -and $l -match '\bFs\b') { $cab = $l; break } }
    if ($cab) {
        $pL = $cab.IndexOf('Ltr'); $pF = [regex]::Match($cab, '\bFs\b').Index
        $mT = [regex]::Match($cab, '(Size|Tamaño)'); $pI = $cab.IndexOf('Info')
        foreach ($l in $o) {
            $mv = [regex]::Match($l, '^\s*\*?\s*(?:Volume|Volumen)\s+(\d+)')
            if (-not $mv.Success) { continue }
            $letra = Get-ColumnaDp $l $pL 3
            if ($letra -notmatch '^[A-Za-z]$') { $letra = '' }
            $info = ''
            if ($pI -ge 0) { $info = Get-ColumnaDp $l $pI 40 }
            $tam = ''
            if ($mT.Success) { $tam = Get-ColumnaDp $l ($mT.Index - 2) 10 }
            $d.Volumenes += [pscustomobject]@{
                Num = [int]$mv.Groups[1].Value; Letra = $letra.ToUpperInvariant(); Fs = (Get-ColumnaDp $l $pF 6)
                Tamano = (ConvertFrom-TamanoDiskpart $tam); Info = $info
            }
        }
    }
    return [pscustomobject]$d
}

function Get-DiscosDp {
    $res = @()
    foreach ($x in @(Get-ListaDiscosDp)) { $res += Get-DetalleDiscoDp -Numero $x.Number -TamanoTexto $x.Tamano }
    return $res
}

function Get-NumeroDiscoDeVolumenDp {
    # Busca la letra en los volúmenes de cada disco ("detail disk", el mismo
    # método que ya funciona al arrancar). Respaldo: "detail volume".
    param([string]$Letra)
    $l1 = $Letra.Substring(0, 1).ToUpperInvariant()
    foreach ($x in @(Get-ListaDiscosDp)) {
        foreach ($v in (Get-DetalleDiscoDp -Numero $x.Number).Volumenes) {
            if ($v.Letra -eq $l1) { return [int]$x.Number }
        }
    }
    $o = Invoke-Diskpart @(('select volume {0}' -f $l1), 'detail volume')
    foreach ($l in $o) {
        $m = [regex]::Match($l, '^\s*\*?\s*(?:Disk|Disco)\s+(\d+)\s')
        if ($m.Success) { return [int]$m.Groups[1].Value }
    }
    return -1
}

function Add-LetrasVolumenesDp {
    # Asigna letra a los volúmenes de datos del disco que no la tengan.
    # (Solo registra el punto de montaje en WinPE; no escribe en el disco.)
    param([int]$Numero)
    $det = Get-DetalleDiscoDp -Numero $Numero
    foreach ($v in $det.Volumenes) {
        if ($v.Letra) { continue }
        if ($v.Info -match '(?i)(hidden|oculto|system|sistema)') { continue }
        if ($v.Tamano -gt 0 -and $v.Tamano -lt 512MB) { continue }
        # Un volumen cifrado con BitLocker (bloqueado) aparece sin sistema de
        # archivos (o RAW): también necesita letra para poder desbloquearlo.
        if ($v.Fs -notmatch '(?i)^(NTFS|FAT32|FAT|exFAT|ReFS)$' -and $v.Tamano -lt 2GB) { continue }
        [void](Invoke-Diskpart @(('select volume {0}' -f $v.Num), 'assign noerr'))
    }
}

function Get-LetrasDisco {
    param([int]$Numero)
    Add-LetrasVolumenesDp -Numero $Numero
    $res = @()
    foreach ($v in (Get-DetalleDiscoDp -Numero $Numero).Volumenes) { if ($v.Letra) { $res += ('{0}:\' -f $v.Letra) } }
    return $res
}

function Find-VolumenEnDisco {
    # Busca el marcador SOLO en los volúmenes del USB identificado
    param([int]$Numero, [string]$Marcador)
    foreach ($l in @(Get-LetrasDisco -Numero $Numero)) {
        if (Test-Path -LiteralPath (Join-Path $l $Marcador)) { return $l }
    }
    return $null
}

function Test-Integridad {
    <#
      ProblemasCodigo: archivos de HERRAMIENTAS faltantes, modificados o sobrantes.
      ProblemasFirmas: bases de ClamAV ausentes, sin firma válida o archivos no oficiales.
    #>
    param([string]$Raiz)
    $codigo = [System.Collections.Generic.List[string]]::new()
    $firmas = [System.Collections.Generic.List[string]]::new()
    $avisos = [System.Collections.Generic.List[string]]::new()
    $Raiz = $Raiz.Substring(0, 2) + '\'
    if (-not (Test-Path -LiteralPath $ArchivoManifiesto)) {
        $codigo.Add('No existe el manifiesto ancla dentro de WinPE (X:\Ancla\manifest.sha256).')
        return [pscustomobject]@{ Ok = $false; FirmasOk = $false; ProblemasCodigo = $codigo; ProblemasFirmas = $firmas; Avisos = $avisos }
    }
    $esperados = @{}
    foreach ($l in [System.IO.File]::ReadAllLines($ArchivoManifiesto, [System.Text.Encoding]::UTF8)) {
        if ($l -match '^([0-9A-Fa-f]{64})\s+(.+)$') { $esperados[$Matches[2].Trim().ToLowerInvariant()] = @($Matches[1].ToUpperInvariant(), $Matches[2].Trim()) }
    }
    if ($esperados.Count -eq 0) { $codigo.Add('El manifiesto ancla está vacío o dañado.') }

    foreach ($k in $esperados.Keys) {
        $hashEsp = $esperados[$k][0]; $rel = $esperados[$k][1]
        if ($rel -match '(^|\\)\.\.(\\|$)' -or $rel.Contains(':')) { $codigo.Add("Entrada de manifiesto no válida: $rel"); continue }
        $ruta = $Raiz + $rel
        if (-not [System.IO.File]::Exists($ruta)) { $codigo.Add("FALTA: $rel"); continue }
        try { if ((Get-HashSha256 $ruta) -ne $hashEsp) { $codigo.Add("MODIFICADO: $rel") } }
        catch { $codigo.Add("ILEGIBLE: $rel ($($_.Exception.Message))") }
    }
    foreach ($f in @(Get-ArchivosVerificables -Raiz $Raiz -Avisos $avisos)) {
        $rel = $f.Substring($Raiz.Length)
        if (Test-ExcluidoDeVerificacion $rel) { continue }
        if (-not $esperados.ContainsKey($rel.ToLowerInvariant())) { $codigo.Add("SOBRANTE: $rel") }
    }
    # Un archivo autorun.inf en cualquier partición del USB es señal de manipulación
    if (Test-Path -LiteralPath (Join-Path $Raiz 'autorun.inf')) { $codigo.Add('SOBRANTE: autorun.inf') }

    $db = $Raiz + 'ClamAV\database'
    $sigtool = $Raiz + 'ClamAV\sigtool.exe'
    if (-not (Test-Path -LiteralPath $db)) {
        $firmas.Add('No existe ClamAV\database (sin firmas antivirus).')
    } else {
        foreach ($o in @(Get-ChildItem -LiteralPath $db -File -Force -ErrorAction SilentlyContinue | Where-Object { @('.cvd', '.sign', '.dat', '.txt') -notcontains $_.Extension.ToLowerInvariant() })) {
            $firmas.Add("Archivo no oficial en la base de firmas: $($o.Name) (se ignorará; ejecute Actualizar-Firmas.ps1)")
        }
        foreach ($n in @('main.cvd', 'daily.cvd', 'bytecode.cvd')) {
            $p = Join-Path $db $n
            if (-not (Test-Path -LiteralPath $p)) { $firmas.Add("Falta la base de firmas $n"); continue }
            if (-not [System.IO.File]::Exists($sigtool)) { continue }
            $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            $out = (& $sigtool ('--info=' + $p) 2>&1 | ForEach-Object { [string]$_ }) -join "`n"
            $ErrorActionPreference = $eap
            if ($out -notmatch 'Verification OK') { $firmas.Add("Firma digital NO válida en $n") }
            else {
                $m = [regex]::Match($out, '(?im)^Build time:\s*(\d{1,2} \w{3} \d{4})')
                if ($m.Success) { $avisos.Add(('{0}: generada el {1}' -f $n, $m.Groups[1].Value)) }
            }
        }
    }
    return [pscustomobject]@{ Ok = ($codigo.Count -eq 0); FirmasOk = ($firmas.Count -eq 0); ProblemasCodigo = $codigo; ProblemasFirmas = $firmas; Avisos = $avisos }
}

function Show-ResultadoIntegridad {
    param($Res, [string]$Huella)
    Write-Host ''
    Write-Host ('HUELLA DEL ANCLA: {0}' -f $Huella) -ForegroundColor Cyan
    Write-Host 'Debe coincidir con HUELLA-ANCLA.txt. La verificación fuerte se hace en el PC técnico con Verificar-USB.ps1.' -ForegroundColor Cyan
    foreach ($a in $Res.Avisos) { Write-Host ('  ' + $a) -ForegroundColor Gray }
    if ($Res.Ok) { Write-Host 'INTEGRIDAD DEL CÓDIGO: CORRECTA' -ForegroundColor Green }
    else {
        Write-Host 'INTEGRIDAD DEL CÓDIGO: FALLIDA' -ForegroundColor Red
        foreach ($p in ($Res.ProblemasCodigo | Select-Object -First 40)) { Write-Host ('  ' + $p) -ForegroundColor Red }
    }
    if ($Res.FirmasOk) { Write-Host 'BASES DE FIRMAS: CORRECTAS' -ForegroundColor Green }
    else { foreach ($p in $Res.ProblemasFirmas) { Write-Host ('  FIRMAS: ' + $p) -ForegroundColor Yellow } }
}

# ---------------------------------------------------------------------------
# Modo solo verificación (lo usa Analizar-Equipo.ps1 al terminar)
# ---------------------------------------------------------------------------
if ($SoloVerificar) {
    if (-not $Herramientas) { Write-Output 'Falta -Herramientas.'; exit 1 }
    $r = Test-Integridad -Raiz $Herramientas
    Write-Output ('Huella: ' + (Get-Huella))
    foreach ($p in $r.ProblemasCodigo) { Write-Output ('PROBLEMA CÓDIGO: ' + $p) }
    foreach ($p in $r.ProblemasFirmas) { Write-Output ('PROBLEMA FIRMAS: ' + $p) }
    foreach ($a in $r.Avisos) { Write-Output ('AVISO: ' + $a) }
    if (-not $r.Ok) { Write-Output 'INTEGRIDAD FALLIDA'; exit 1 }
    if (-not $r.FirmasOk) { Write-Output 'CÓDIGO CORRECTO, AVISOS EN FIRMAS'; exit 2 }
    Write-Output 'INTEGRIDAD CORRECTA'; exit 0
}

# ---------------------------------------------------------------------------
# Arranque normal
# ---------------------------------------------------------------------------
Clear-Host
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host '  USB FORENSE - análisis sin conexión y respaldo seguro' -ForegroundColor Cyan
Write-Host '==============================================================' -ForegroundColor Cyan

try {
    $sb = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction Stop
    if ([int]$sb.UEFISecureBootEnabled -eq 1) { Write-Host 'Secure Boot: ACTIVO' -ForegroundColor Green }
    else { Write-Host 'Secure Boot: INACTIVO (vuelva a activarlo en la UEFI cuando termine)' -ForegroundColor Yellow }
} catch { Write-Host 'Secure Boot: no se pudo determinar' -ForegroundColor Yellow }

# 1) Discos
$idUsb = Get-IdUsbEsperado
if ($null -eq $idUsb) {
    Write-Host 'Falta la identidad del USB en el ancla (X:\Ancla\usb-id.txt). Reconstruya el USB con Crear-USB.ps1.' -ForegroundColor Red
    exit 1
}
$idTxt = '{0:X8}' -f $idUsb
$discos = @()
# Pequeña espera y reintentos: algunos equipos tardan en presentar los discos
for ($intento = 1; $intento -le 5 -and $discos.Count -eq 0; $intento++) {
    $discos = @(Get-ListaDiscosDp)
    if ($discos.Count -eq 0) { Start-Sleep -Seconds 3 }
}
if ($discos.Count -eq 0) { Write-Host 'diskpart no muestra ningún disco.' -ForegroundColor Red; exit 1 }
$usbNumero = -1
foreach ($x in $discos) {
    $n = [int]$x.Number
    try {
        $d = Get-DetalleDiscoDp -Numero $n -TamanoTexto $x.Tamano
        $esUsb = ($d.PartitionStyle -eq 'MBR' -and $d.Id -eq $idTxt -and $usbNumero -lt 0)
        if ($esUsb) {
            [void](Invoke-Diskpart @("select disk $n", 'attributes disk clear readonly noerr', 'online disk noerr'))
            Start-Sleep -Seconds 2
            $usbNumero = $n
            Write-Host ('USB de trabajo: disco #{0} ({1}), firma {2}.' -f $n, $d.FriendlyName, $idTxt) -ForegroundColor Green
            continue
        }
        # Cualquier otro disco: fuera de línea y solo lectura. Nunca se le quita la protección.
        if (-not $d.IsOffline) {
            Write-Host ('AVISO: el disco #{0} ({1}) estaba en línea. Se protege ahora.' -f $n, $d.FriendlyName) -ForegroundColor Yellow
        }
        [void](Invoke-Diskpart @("select disk $n", 'offline disk noerr', 'attributes disk set readonly noerr'))
        $d2 = Get-DetalleDiscoDp -Numero $n
        $estado = 'protegido'
        if (-not $d2.IsReadOnly) { $estado = 'fuera de línea (atributo de solo lectura pendiente: se aplicará al analizar)' }
        Write-Host ('Disco #{0} ({1}, {2}, {3}): {4}.' -f $n, $d.FriendlyName, $d.BusType, $x.Tamano, $estado) -ForegroundColor Gray
    } catch {
        Write-Host ('No se pudo proteger el disco #{0}: {1}' -f $n, $_.Exception.Message) -ForegroundColor Red
    }
}
if ($usbNumero -lt 0) {
    Write-Host ('No se encontró el USB con la firma {0}. ¿Es el USB correcto? Si lo reparticionó, reconstrúyalo.' -f $idTxt) -ForegroundColor Red
    foreach ($x in $discos) { Write-Host ('  disco #{0}: firma {1}' -f $x.Number, (Get-DetalleDiscoDp -Numero $x.Number).Id) -ForegroundColor Gray }
    exit 1
}

# 2) Particiones del USB (solo dentro del disco identificado)
$H = Find-VolumenEnDisco -Numero $usbNumero -Marcador $MarcadorHerramientas
$R = Find-VolumenEnDisco -Numero $usbNumero -Marcador $MarcadorRespaldo
if (-not $H -or -not $R) {
    Write-Host 'No se encontraron las particiones HERRAMIENTAS y/o RESPALDO en el USB identificado.' -ForegroundColor Red
    exit 1
}
Write-Host ('HERRAMIENTAS = {0}   RESPALDO = {1}' -f $H, $R) -ForegroundColor Green

# Temporales de ejecuciones interrumpidas (copias de hives / extracciones de ClamAV)
foreach ($t in @(Get-ChildItem -LiteralPath (Join-Path $R 'Casos') -Directory -ErrorAction SilentlyContinue)) {
    $tw = Join-Path $t.FullName 'Trabajo'
    if (Test-Path -LiteralPath $tw) {
        try { Remove-Item -LiteralPath $tw -Recurse -Force -ErrorAction Stop; Write-Host ('Temporales antiguos eliminados: {0}' -f $tw) -ForegroundColor Gray } catch { }
    }
}

# 3) Integridad
$huella = Get-Huella
$res = Test-Integridad -Raiz $H
Show-ResultadoIntegridad -Res $res -Huella $huella
$integridadTxt = 'CORRECTA'
if (-not $res.FirmasOk) { $integridadTxt = 'CORRECTA (avisos en firmas)' }
$puedeAnalizar = $res.Ok

# 4) Copiar los scripts verificados a la RAM y comprobarlos otra vez
$ram = 'X:\Trabajo\Scripts'
if ($puedeAnalizar) {
    if (Test-Path -LiteralPath $ram) { Remove-Item -LiteralPath $ram -Recurse -Force }
    New-Item -ItemType Directory -Path $ram -Force | Out-Null
    Copy-Item -Path (Join-Path $H 'Scripts\*') -Destination $ram -Recurse -Force
    $manif = @{}
    foreach ($l in [System.IO.File]::ReadAllLines($ArchivoManifiesto, [System.Text.Encoding]::UTF8)) {
        if ($l -match '^([0-9A-Fa-f]{64})\s+(.+)$') { $manif[$Matches[2].Trim().ToLowerInvariant()] = $Matches[1].ToUpperInvariant() }
    }
    foreach ($f in [System.IO.Directory]::GetFiles($ram, '*', [System.IO.SearchOption]::AllDirectories)) {
        $rel = ('Scripts\' + $f.Substring($ram.Length + 1)).ToLowerInvariant()
        if (-not $manif.ContainsKey($rel) -or (Get-HashSha256 $f) -ne $manif[$rel]) {
            Write-Host ("La copia en RAM no coincide con el ancla: {0}" -f $rel) -ForegroundColor Red
            $puedeAnalizar = $false
        }
    }
}
if (-not $puedeAnalizar) {
    Write-Host ''
    Write-Host 'El código del USB NO es íntegro: el análisis queda BLOQUEADO (no existe anulación manual).' -ForegroundColor Red
    Write-Host 'Reconstruya el USB en el PC técnico con Crear-USB.ps1, o use Actualizar-Ancla.ps1 si usted cambió los scripts.' -ForegroundColor Red
}

# 5) Menú
while ($true) {
    Write-Host ''
    Write-Host '--------------------------- MENÚ ---------------------------' -ForegroundColor Cyan
    if ($puedeAnalizar) {
        Write-Host '  1. RESCATE SEGURO: analizar el equipo y respaldar archivos (flujo completo)'
        Write-Host '  2. RECUPERACIÓN AVANZADA (TITAN BLACKBOX): archivos dañados, imagen, particiones, firmas'
    } else {
        Write-Host '  1. (bloqueado: integridad fallida)' -ForegroundColor DarkGray
        Write-Host '  2. (bloqueado: integridad fallida)' -ForegroundColor DarkGray
    }
    Write-Host '  3. Verificar otra vez la integridad del USB'
    Write-Host '  4. Abrir una consola (cmd)'
    Write-Host '  5. Reiniciar'
    Write-Host '  6. Apagar'
    $op = ([string](Read-Host 'Opción')).Trim()
    switch ($op) {
        '1' {
            if (-not $puedeAnalizar) { Write-Host 'Bloqueado.' -ForegroundColor Red; break }
            & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ram 'Analizar-Equipo.ps1') -RutaHerramientas $H -RutaRespaldo $R -Huella $huella -IntegridadInicial $integridadTxt
        }
        '2' {
            if (-not $puedeAnalizar) { Write-Host 'Bloqueado.' -ForegroundColor Red; break }
            & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ram 'Blackbox.ps1') -RutaHerramientas $H -RutaRespaldo $R -Huella $huella -IntegridadInicial $integridadTxt
        }
        '3' { $res2 = Test-Integridad -Raiz $H; Show-ResultadoIntegridad -Res $res2 -Huella (Get-Huella); if (-not $res2.Ok) { $puedeAnalizar = $false } }
        '4' { Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') }
        '5' { & (Join-Path $env:SystemRoot 'System32\wpeutil.exe') reboot }
        '6' { & (Join-Path $env:SystemRoot 'System32\wpeutil.exe') shutdown }
        default { Write-Host 'Opción no válida.' -ForegroundColor Yellow }
    }
}
