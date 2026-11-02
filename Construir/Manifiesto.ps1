<#
    Manifiesto.ps1 - Funciones compartidas por los scripts de construcción
    (se cargan con dot-sourcing). Generan y comprueban el manifiesto SHA-256
    de la partición HERRAMIENTAS.

    Formato de cada línea:  <SHA256 en mayúsculas><dos espacios><ruta relativa>
    Exclusiones (deben coincidir con X:\Ancla\Iniciar.ps1):
      - ClamAV\database\  (las .cvd se verifican por firma digital)
      - System Volume Information\ y $RECYCLE.BIN\
#>

function Test-ExcluidoDelManifiesto {
    param([string]$Relativa)
    return ($Relativa -match '(?i)^(System Volume Information|\$RECYCLE\.BIN)\\' -or $Relativa -match '(?i)^ClamAV\\database\\')
}

function Get-HashSha256Archivo {
    param([string]$Ruta)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Ruta)
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '') }
    finally { $fs.Dispose(); $sha.Dispose() }
}

function Get-ArchivosParaManifiesto {
    # Recorrido propio: EnumerateFiles(AllDirectories) aborta entero al llegar a
    # "System Volume Information" (acceso denegado) en una partición NTFS.
    param([string]$Base)
    $raiz = $Base.TrimEnd('\') + '\'          # 'H:\' (nunca 'H:', que sería la carpeta actual de H)
    $pila = New-Object System.Collections.Generic.Stack[string]
    $pila.Push($raiz)
    while ($pila.Count -gt 0) {
        $dir = $pila.Pop()
        $rel = ''
        if ($dir.Length -gt $raiz.Length) { $rel = $dir.Substring($raiz.Length).TrimEnd('\') + '\' }
        if ($rel -and (Test-ExcluidoDelManifiesto $rel)) { continue }
        try {
            foreach ($f in [System.IO.Directory]::GetFiles($dir)) { $f }
            foreach ($d in [System.IO.Directory]::GetDirectories($dir)) {
                $attr = [System.IO.File]::GetAttributes($d)
                if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $pila.Push($d) }
            }
        } catch {
            if (-not $rel) { throw }
            Write-Host ("  (sin acceso a {0}: {1})" -f $dir, $_.Exception.Message) -ForegroundColor DarkYellow
        }
    }
}

function New-Manifiesto {
    param([Parameter(Mandatory = $true)][string]$Raiz, [Parameter(Mandatory = $true)][string]$Salida)
    $base = (Resolve-Path -LiteralPath $Raiz).ProviderPath.TrimEnd('\') + '\'
    $lineas = New-Object System.Collections.Generic.List[string]
    foreach ($f in @(Get-ArchivosParaManifiesto -Base $base)) {
        $rel = $f.Substring($base.Length)
        if (Test-ExcluidoDelManifiesto $rel) { continue }
        $lineas.Add(('{0}  {1}' -f (Get-HashSha256Archivo $f), $rel))
    }
    $ordenadas = @($lineas | Sort-Object { $_.Substring(66) })
    [System.IO.File]::WriteAllLines($Salida, [string[]]$ordenadas, (New-Object System.Text.UTF8Encoding($false)))
    return $ordenadas.Count
}

function Get-HuellaManifiesto {
    param([string]$Archivo)
    $h = Get-HashSha256Archivo $Archivo
    return ('{0}-{1}-{2}-{3}' -f $h.Substring(0, 4), $h.Substring(4, 4), $h.Substring(8, 4), $h.Substring(12, 4))
}

function Test-ManifiestoEnRuta {
    # Devuelve la lista de problemas (vacía = correcto)
    param([string]$Raiz, [string]$Manifiesto, [string]$SoloPrefijo = '')
    $base = $Raiz.TrimEnd('\') + '\'
    $problemas = New-Object System.Collections.Generic.List[string]
    $esperados = @{}
    foreach ($l in [System.IO.File]::ReadAllLines($Manifiesto)) {
        if ($l -match '^([0-9A-Fa-f]{64})\s+(.+)$') { $esperados[$Matches[2].Trim().ToLowerInvariant()] = @($Matches[1].ToUpperInvariant(), $Matches[2].Trim()) }
    }
    foreach ($k in $esperados.Keys) {
        if ($SoloPrefijo -and -not $k.StartsWith($SoloPrefijo.ToLowerInvariant())) { continue }
        $ruta = $base + $esperados[$k][1]
        if (-not [System.IO.File]::Exists($ruta)) { $problemas.Add('FALTA: ' + $esperados[$k][1]); continue }
        if ((Get-HashSha256Archivo $ruta) -ne $esperados[$k][0]) { $problemas.Add('MODIFICADO: ' + $esperados[$k][1]) }
    }
    if (-not $SoloPrefijo) {
        foreach ($f in @(Get-ArchivosParaManifiesto -Base $base)) {
            $rel = $f.Substring($base.Length)
            if (Test-ExcluidoDelManifiesto $rel) { continue }
            if (-not $esperados.ContainsKey($rel.ToLowerInvariant())) { $problemas.Add('SOBRANTE: ' + $rel) }
        }
    }
    return , $problemas
}

function Get-RutaSistema {
    # Ruta absoluta a herramientas de Windows (evita secuestro por PATH)
    param([string]$Programa)
    $p = Join-Path $env:SystemRoot ('System32\' + $Programa)
    if (Test-Path -LiteralPath $p) { return $p }
    throw "No se encontró $p"
}

function Test-FirmaAuthenticode {
    # $true si el archivo tiene firma Authenticode válida de un editor que contiene $Sujeto
    param([string]$Ruta, [string]$Sujeto)
    $s = Get-AuthenticodeSignature -LiteralPath $Ruta
    return ([string]$s.Status -eq 'Valid' -and $s.SignerCertificate -and $s.SignerCertificate.Subject -like "*$Sujeto*")
}

function Get-UsbForense {
    <#
      Localiza el USB forense por su FIRMA DE DISCO (C:\WinPE_USBForense\usb-id.txt),
      no solo por marcadores. Devuelve número de disco y letras WINPE/HERRAMIENTAS/RESPALDO.
    #>
    param([string]$Trabajo)
    $archivoId = Join-Path $Trabajo 'usb-id.txt'
    if (-not (Test-Path -LiteralPath $archivoId)) { throw "No existe $archivoId (identidad del USB). Cree el USB con Crear-USB.ps1." }
    $id = [Convert]::ToUInt32(([System.IO.File]::ReadAllText($archivoId)).Trim(), 16)
    $idTxt = '{0:X8}' -f $id
    $res = [ordered]@{ Disco = -1; Id = $idTxt; P = $null; H = $null; R = $null }
    $letras = @()
    # 1) Cmdlets de almacenamiento (rápidos). Su caché a veces queda desactualizada.
    try {
        try { Update-HostStorageCache -ErrorAction Stop } catch { }
        $disco = @(Get-Disk -ErrorAction Stop | Where-Object { [string]$_.PartitionStyle -eq 'MBR' -and $null -ne $_.Signature -and [uint32]$_.Signature -eq $id })
        if ($disco.Count -eq 1) {
            $res.Disco = [int]$disco[0].Number
            foreach ($p in @(Get-Partition -DiskNumber $res.Disco -ErrorAction Stop)) {
                $c = [int][char]$p.DriveLetter
                if ($c -ne 0) { $letras += ('{0}:' -f [char]$c) }
            }
        }
    } catch { $res.Disco = -1; $letras = @() }
    # 2) Respaldo con diskpart (siempre ve la firma real)
    if ($res.Disco -lt 0) {
        $hallados = @()
        foreach ($x in @(Get-ListaDiscosDp)) {
            $d = Get-DetalleDiscoDp -Numero $x.Number -TamanoTexto $x.Tamano
            if ($d.Id -eq $idTxt) { $hallados += $d }
        }
        if ($hallados.Count -ne 1) { throw ('No se encontró (o hay más de un) disco con la firma {0}. Conecte el USB forense.' -f $idTxt) }
        $res.Disco = [int]$hallados[0].Number
        foreach ($v in $hallados[0].Volumenes) { if ($v.Letra) { $letras += ('{0}:' -f $v.Letra) } }
    }
    foreach ($l in $letras) {
        if (Test-Path -LiteralPath "$l\sources\boot.wim") { $res.P = $l }
        elseif (Test-Path -LiteralPath "$l\USB-FORENSE.marker") { $res.H = $l }
        elseif (Test-Path -LiteralPath "$l\RESPALDO.marker") { $res.R = $l }
    }
    if (-not $res.P -or -not $res.H -or -not $res.R) { throw 'El USB no tiene las tres particiones esperadas con letra (WINPE, HERRAMIENTAS, RESPALDO).' }
    return [pscustomobject]$res
}

function Invoke-VerificacionUsb {
    <#
      Verificación FUERTE desde el PC técnico (entorno de confianza):
        1. Partición WINPE (boot.wim con el ancla, bootx64.efi, BCD...) contra
           referencia_winpe.sha256 guardada en este PC al crear el USB.
        2. HERRAMIENTAS contra manifest.sha256 (faltantes, modificados, sobrantes).
        3. Bases .cvd de ClamAV con firma digital válida (sigtool, ya verificado).
        4. Restos peligrosos: autorun.inf, temporales de análisis interrumpidos,
           ejecutables sueltos en la raíz de RESPALDO.
    #>
    param([string]$Trabajo, [switch]$SinFirmas)
    $problemas = New-Object System.Collections.Generic.List[string]
    $avisos = New-Object System.Collections.Generic.List[string]
    $usb = Get-UsbForense -Trabajo $Trabajo
    $refWinPE = Join-Path $Trabajo 'referencia_winpe.sha256'
    $manif = Join-Path $Trabajo 'manifest.sha256'

    if (Test-Path -LiteralPath $refWinPE) {
        foreach ($x in (Test-ManifiestoEnRuta -Raiz "$($usb.P)\" -Manifiesto $refWinPE)) { $problemas.Add("WINPE $x") }
    } else { $problemas.Add(('No existe {0}: no se puede verificar la partición de arranque.' -f $refWinPE)) }

    if (Test-Path -LiteralPath $manif) {
        foreach ($x in (Test-ManifiestoEnRuta -Raiz "$($usb.H)\" -Manifiesto $manif)) { $problemas.Add("HERRAMIENTAS $x") }
    } else { $problemas.Add("No existe $manif.") }

    foreach ($l in @($usb.P, $usb.H, $usb.R)) {
        if (Test-Path -LiteralPath "$l\autorun.inf") { $problemas.Add("autorun.inf presente en $l") }
    }
    foreach ($f in @(Get-ChildItem -LiteralPath "$($usb.R)\" -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Extension -match '^\.(exe|com|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|dll|msi|pif)$') { $problemas.Add("Archivo ejecutable inesperado en RESPALDO: $($f.Name)") }
    }
    foreach ($t in @(Get-ChildItem -LiteralPath "$($usb.R)\Casos" -Directory -ErrorAction SilentlyContinue)) {
        if (Test-Path -LiteralPath (Join-Path $t.FullName 'Trabajo')) { $avisos.Add("Temporales de un análisis interrumpido: $($t.FullName)\Trabajo (pueden contener malware sin cifrar)") }
    }

    $herramientasOk = -not ($problemas | Where-Object { $_ -like 'HERRAMIENTAS*' })
    if (-not $SinFirmas -and $herramientasOk) {
        $db = "$($usb.H)\ClamAV\database"
        $sigtool = "$($usb.H)\ClamAV\sigtool.exe"
        foreach ($n in @('main.cvd', 'daily.cvd', 'bytecode.cvd')) {
            $p = Join-Path $db $n
            if (-not (Test-Path -LiteralPath $p)) { $problemas.Add("Falta la base de firmas $n"); continue }
            $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            $out = (& $sigtool ('--info=' + $p) 2>&1 | ForEach-Object { [string]$_ }) -join "`n"
            $ErrorActionPreference = $eap
            if ($out -notmatch 'Verification OK') { $problemas.Add("Firma digital NO válida en $n") }
        }
        foreach ($o in @(Get-ChildItem -LiteralPath $db -File -Force -ErrorAction SilentlyContinue | Where-Object { @('.cvd', '.sign', '.dat', '.txt') -notcontains $_.Extension.ToLowerInvariant() })) {
            $problemas.Add("Archivo no oficial en la base de firmas: $($o.Name)")
        }
    }
    return [pscustomobject]@{ Ok = ($problemas.Count -eq 0); Problemas = $problemas; Avisos = $avisos; Usb = $usb }
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

function Write-Paso {
    param([string]$Texto)
    Write-Host ''
    Write-Host ('>>> ' + $Texto) -ForegroundColor Cyan
}
