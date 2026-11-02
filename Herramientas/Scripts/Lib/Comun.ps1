<#
    Comun.ps1 - Utilidades compartidas del analizador.
    Se carga con dot-sourcing desde Analizar-Equipo.ps1 (comparten el mismo ámbito).
    Compatible con Windows PowerShell 5.1 (componente WinPE-PowerShell).
    No usa sintaxis exclusiva de PowerShell 7 (??, ?:, &&, -Parallel, etc.).
#>

# ---------------------------------------------------------------------------
# Estado global compartido
# ---------------------------------------------------------------------------
$script:Utf8SinBom       = New-Object System.Text.UTF8Encoding($false)
$script:Utf8ConBom       = New-Object System.Text.UTF8Encoding($true)
# Clave convencional (pública) para cifrar la cuarentena. El objetivo NO es
# esconder el archivo sino volverlo inerte: no se puede ejecutar ni lo
# detectan/abren otros programas por accidente.
$script:ClaveCuarentena  = 'infected'
$script:SoportaRutaLarga = $false
$script:Errores          = [System.Collections.Generic.List[object]]::new()
$script:ArchivoLog       = $null

# Atributos de archivo relevantes (valores de la API de Windows)
$script:ATTR_DIRECTORIO  = 0x10
$script:ATTR_REPARSE     = 0x400
$script:ATTR_OFFLINE     = 0x1000
$script:ATTR_RECALL_OPEN = 0x40000
$script:ATTR_RECALL_DATA = 0x400000

# ---------------------------------------------------------------------------
# Registro (log) y errores
# ---------------------------------------------------------------------------
function Initialize-Registro {
    param([Parameter(Mandatory = $true)][string]$ArchivoLog)
    $script:ArchivoLog = $ArchivoLog
    [System.IO.File]::WriteAllText($ArchivoLog, '', $script:Utf8ConBom)
}

function ConvertTo-TextoSeguro {
    <#
      Neutraliza texto que viene del equipo analizado (nombres de archivo,
      valores del registro) antes de mostrarlo o registrarlo:
        - saltos de línea -> ' | '  (evita falsificar líneas del registro)
        - caracteres de control (ESC, BEL...) -> '?'  (evita secuencias de terminal)
        - controles bidireccionales (RLO, LRO...) -> '[U+202E]' visible
          (evita que "fdp.exe" se muestre como "exe.pdf")
    #>
    param($Texto)
    if ($null -eq $Texto) { return '' }
    $s = [string]$Texto
    $s = $s -replace "`r`n|`r|`n", ' | '
    $s = [regex]::Replace($s, '[‪-‮⁦-⁩‎‏]', { param($m) '[U+{0:X4}]' -f [int][char]$m.Value })
    $s = $s -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '?'
    return $s
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Mensaje,
        [ValidateSet('INFO', 'OK', 'AVISO', 'ERROR', 'FASE', 'DET')][string]$Nivel = 'INFO',
        [switch]$SoloArchivo
    )
    $Mensaje = ConvertTo-TextoSeguro $Mensaje
    $linea = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Nivel, $Mensaje
    if ($script:ArchivoLog) {
        try { [System.IO.File]::AppendAllText($script:ArchivoLog, $linea + "`r`n", $script:Utf8SinBom) } catch { }
    }
    if (-not $SoloArchivo) {
        $color = 'Gray'
        switch ($Nivel) {
            'OK'    { $color = 'Green' }
            'AVISO' { $color = 'Yellow' }
            'ERROR' { $color = 'Red' }
            'FASE'  { $color = 'Cyan' }
            'DET'   { $color = 'Magenta' }
        }
        if ($Nivel -eq 'FASE') { Write-Host ''; Write-Host ('=' * 72) -ForegroundColor Cyan }
        Write-Host $Mensaje -ForegroundColor $color
        if ($Nivel -eq 'FASE') { Write-Host ('=' * 72) -ForegroundColor Cyan }
    }
}

function Add-RegistroError {
    param([string]$Fase, [string]$Ruta, [string]$Mensaje, [switch]$Silencioso)
    $script:Errores.Add([pscustomobject]@{
            Fecha   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Fase    = $Fase
            Ruta    = $Ruta
            Mensaje = $Mensaje
        })
    $texto = '[{0}] {1} :: {2}' -f $Fase, $Ruta, $Mensaje
    if ($Silencioso) { Write-Log $texto -Nivel ERROR -SoloArchivo } else { Write-Log $texto -Nivel ERROR }
}

# ---------------------------------------------------------------------------
# Interacción con el usuario
# ---------------------------------------------------------------------------
function Read-Confirmacion {
    param([string]$Pregunta, [string]$Palabra = 'SI')
    $r = Read-Host ("{0}  (escriba {1} para continuar)" -f $Pregunta, $Palabra)
    return (([string]$r).Trim().ToUpperInvariant() -eq $Palabra.ToUpperInvariant())
}

function Read-Opcion {
    # Devuelve la letra elegida (en mayúscula). $Opciones = @('N','R','S')
    param([string]$Pregunta, [string[]]$Opciones, [string]$PorDefecto)
    while ($true) {
        $r = ([string](Read-Host $Pregunta)).Trim().ToUpperInvariant()
        if ($r -eq '' -and $PorDefecto) { return $PorDefecto.ToUpperInvariant() }
        if ($Opciones -contains $r) { return $r }
        Write-Host ("Opción no válida. Use: {0}" -f ($Opciones -join ', ')) -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Formato
# ---------------------------------------------------------------------------
function Format-Bytes {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    return ('{0:N0} B' -f $Bytes)
}

function Format-Duracion {
    param([TimeSpan]$Duracion)
    return ('{0:00}h {1:00}m {2:00}s' -f [Math]::Floor($Duracion.TotalHours), $Duracion.Minutes, $Duracion.Seconds)
}

# ---------------------------------------------------------------------------
# CSV (separador ';' para que Excel en español lo abra en columnas)
# Los datos vienen de un equipo posiblemente comprometido: se neutralizan
# valores que Excel interpretaría como fórmulas (=, +, -, @).
# ---------------------------------------------------------------------------
function ConvertTo-CampoCsv {
    param($Valor)
    if ($null -eq $Valor) { return '' }
    $s = [string]$Valor
    # Inyección de fórmulas (OWASP): =, +, -, @, tabulador y retorno al inicio
    if ($s.Length -gt 0 -and ("=+-@`t`r").IndexOf($s[0]) -ge 0) { $s = "'" + $s }
    if ($s.IndexOfAny([char[]]@(';', '"', "`r", "`n")) -ge 0) {
        return '"' + $s.Replace('"', '""') + '"'
    }
    return $s
}

function New-EscritorCsv {
    param([string]$Ruta, [string[]]$Columnas)
    $w = New-Object System.IO.StreamWriter -ArgumentList $Ruta, $false, $script:Utf8ConBom
    $w.WriteLine((($Columnas | ForEach-Object { ConvertTo-CampoCsv $_ }) -join ';'))
    return $w
}

function Write-FilaCsv {
    param($Escritor, [object[]]$Valores)
    $campos = [System.Collections.Generic.List[string]]::new()
    foreach ($v in $Valores) { $campos.Add((ConvertTo-CampoCsv $v)) }
    $Escritor.WriteLine(($campos -join ';'))
}

function Export-ListaCsv {
    # Exporta una lista de objetos usando las propiedades indicadas como columnas.
    param([string]$Ruta, $Objetos, [string[]]$Columnas)
    $w = New-EscritorCsv -Ruta $Ruta -Columnas $Columnas
    try {
        # Sin @(...): en PowerShell 5.1 @() sobre una lista genérica envuelta da
        # "Argument types do not match" (visto en un portátil y reproducido en otro PC).
        foreach ($o in $Objetos) {
            if ($null -eq $o) { continue }
            # Lista explícita: conserva los valores $null y no desplaza columnas
            $vals = [System.Collections.Generic.List[object]]::new()
            foreach ($c in $Columnas) { $vals.Add($o.$c) }
            Write-FilaCsv -Escritor $w -Valores $vals.ToArray()
        }
    } finally { $w.Dispose() }
}

# ---------------------------------------------------------------------------
# Rutas largas (> 260 caracteres) usando el prefijo \\?\ cuando .NET lo admite
# ---------------------------------------------------------------------------
function Initialize-RutasLargas {
    try {
        $script:SoportaRutaLarga = [System.IO.Directory]::Exists('\\?\' + $env:SystemDrive + '\')
    } catch { $script:SoportaRutaLarga = $false }
}

function Get-RutaLarga {
    param([string]$Ruta)
    if ($script:SoportaRutaLarga -and -not $Ruta.StartsWith('\\?\') -and $Ruta -match '^[A-Za-z]:\\') {
        return ('\\?\' + $Ruta)
    }
    return $Ruta
}

function Get-RutaCorta {
    param([string]$Ruta)
    if ($Ruta.StartsWith('\\?\')) { return $Ruta.Substring(4) }
    return $Ruta
}

function Test-RutaDentroDe {
    # ¿$Ruta está dentro de la carpeta $Carpeta? (comparación sin mayúsculas)
    param([string]$Ruta, [string]$Carpeta)
    $c = $Carpeta.TrimEnd('\') + '\'
    return $Ruta.StartsWith($c, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-ArchivoExiste {
    param([string]$Ruta)
    try { return [System.IO.File]::Exists((Get-RutaLarga $Ruta)) } catch { return $false }
}

# ---------------------------------------------------------------------------
# Atributos
# ---------------------------------------------------------------------------
function Test-EsEnlaceSimbolico {
    # Lee la etiqueta del punto de reanálisis con fsutil (solo lectura).
    # a000000c = enlace simbólico, a0000003 = unión/punto de montaje.
    param([string]$Ruta)
    $r = Invoke-Nativo 'fsutil.exe' @('reparsepoint', 'query', $Ruta)
    $m = [regex]::Match(($r.Salida -join ' '), '0x([0-9a-fA-F]{8})')
    if (-not $m.Success) { return $false }
    return (@('a000000c', 'a0000003') -contains $m.Groups[1].Value.ToLowerInvariant())
}

function Test-SoloNube {
    # Marcadores de posición de OneDrive/nube: el contenido no está en el disco.
    param([int]$Atributos)
    return ((($Atributos -band $script:ATTR_OFFLINE) -ne 0) -or
        (($Atributos -band $script:ATTR_RECALL_OPEN) -ne 0) -or
        (($Atributos -band $script:ATTR_RECALL_DATA) -ne 0))
}

# ---------------------------------------------------------------------------
# Enumeración recursiva en streaming (no carga todo en memoria).
# - No sigue uniones/enlaces simbólicos de carpeta (evita bucles).
# - Incluye archivos ocultos y de sistema.
# - Los errores de acceso se registran y se continúa.
# Emite objetos FileInfo (su FullName puede llevar el prefijo \\?\).
# ---------------------------------------------------------------------------
function Get-ArchivosRecursivo {
    param(
        [Parameter(Mandatory = $true)][string]$Raiz,
        [string]$Fase = 'Inventario',
        [string[]]$ExcluirNombresCarpeta = @()
    )
    $pila = [System.Collections.Generic.Stack[string]]::new()
    $pila.Push((Get-RutaLarga ($Raiz.TrimEnd('\') + '\')))
    while ($pila.Count -gt 0) {
        $dir = $pila.Pop()
        $entradas = $null
        try {
            $di = New-Object System.IO.DirectoryInfo -ArgumentList $dir
            $entradas = $di.GetFileSystemInfos()
        } catch {
            Add-RegistroError -Fase $Fase -Ruta (Get-RutaCorta $dir) -Mensaje $_.Exception.Message -Silencioso
            continue
        }
        foreach ($e in $entradas) {
            $attr = [int]$e.Attributes
            if (($attr -band $script:ATTR_DIRECTORIO) -ne 0) {
                if (($attr -band $script:ATTR_REPARSE) -ne 0) {
                    Write-Log ("Carpeta enlace/unión omitida: {0}" -f (Get-RutaCorta $e.FullName)) -SoloArchivo
                    continue
                }
                if ($ExcluirNombresCarpeta -contains $e.Name) { continue }
                $pila.Push($e.FullName)
            } else {
                $e
            }
        }
    }
}

# ---------------------------------------------------------------------------
# SHA-256 en streaming. Devuelve Hash (hex mayúsculas) y los primeros 8 bytes
# (para heurísticas de tipo real del archivo). Solo LEE el archivo.
# ---------------------------------------------------------------------------
function Get-Sha256Archivo {
    param([Parameter(Mandatory = $true)][string]$Ruta)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream -ArgumentList (Get-RutaLarga $Ruta),
            ([System.IO.FileMode]::Open), ([System.IO.FileAccess]::Read),
            ([System.IO.FileShare]'ReadWrite, Delete'), 1048576,
            ([System.IO.FileOptions]::SequentialScan)
        $buf = New-Object byte[] 1048576
        $cab = $null
        while ($true) {
            $n = $fs.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            if ($null -eq $cab) {
                $m = [Math]::Min($n, 8)
                $cab = New-Object byte[] $m
                [Array]::Copy($buf, $cab, $m)
            }
            [void]$sha.TransformBlock($buf, 0, $n, $null, 0)
        }
        [void]$sha.TransformFinalBlock($buf, 0, 0)
        if ($null -eq $cab) { $cab = New-Object byte[] 0 }
        return [pscustomobject]@{
            Hash     = ([System.BitConverter]::ToString($sha.Hash)).Replace('-', '')
            Cabecera = $cab
        }
    } finally {
        if ($fs) { $fs.Dispose() }
        $sha.Dispose()
    }
}

# ---------------------------------------------------------------------------
# Cuarentena: copia CIFRADA (AES-256-CBC, clave derivada de 'infected').
# Formato: 'CUAR1' + sal(16) + IV(16) + datos cifrados.
# Respaldo si AES no está disponible en WinPE: 'CUARX' + XOR 0x5A (máx. 50 MB).
# El archivo original NUNCA se modifica ni se borra.
# ---------------------------------------------------------------------------
function Protect-ArchivoCuarentena {
    param([Parameter(Mandatory = $true)][string]$Origen, [Parameter(Mandatory = $true)][string]$Destino)
    $entrada = $null; $salida = $null; $aes = $null; $kdf = $null
    try {
        $sal = New-Object byte[] 16
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($sal); $rng.Dispose()
        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $script:ClaveCuarentena, $sal, 10000
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.KeySize = 256
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $kdf.GetBytes(32)
        $aes.GenerateIV()
        $entrada = New-Object System.IO.FileStream -ArgumentList (Get-RutaLarga $Origen),
            ([System.IO.FileMode]::Open), ([System.IO.FileAccess]::Read), ([System.IO.FileShare]'ReadWrite, Delete')
        $salida = New-Object System.IO.FileStream -ArgumentList $Destino,
            ([System.IO.FileMode]::CreateNew), ([System.IO.FileAccess]::Write), ([System.IO.FileShare]::None)
        $magia = [System.Text.Encoding]::ASCII.GetBytes('CUAR1')
        $salida.Write($magia, 0, $magia.Length)
        $salida.Write($sal, 0, 16)
        $salida.Write($aes.IV, 0, 16)
        $cifrador = $aes.CreateEncryptor()
        $modo = [System.Security.Cryptography.CryptoStreamMode]::Write
        $cs = New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($salida, $cifrador, $modo)
        $entrada.CopyTo($cs, 1048576)
        $cs.FlushFinalBlock()
        $cs.Dispose()          # cierra también $salida
        $salida = $null
        return 'AES'
    } catch {
        # Limpieza del archivo parcial (es NUESTRO archivo en el USB, no del equipo)
        if ($salida) { $salida.Dispose(); $salida = $null }
        if (Test-Path -LiteralPath $Destino) { Remove-Item -LiteralPath $Destino -Force -ErrorAction SilentlyContinue }
        # Errores de E/S (sector dañado, destino lleno...) se propagan tal cual;
        # solo si falla la criptografía de .NET se usa el modo XOR de respaldo.
        $base = $_.Exception.GetBaseException()
        if ($base -is [System.IO.IOException] -or $base -is [System.UnauthorizedAccessException]) { throw }
        return (Protect-ArchivoCuarentenaXor -Origen $Origen -Destino $Destino)
    } finally {
        if ($entrada) { $entrada.Dispose() }
        if ($salida) { $salida.Dispose() }
        if ($aes) { $aes.Dispose() }
        if ($kdf) { $kdf.Dispose() }
    }
}

function Protect-ArchivoCuarentenaXor {
    param([string]$Origen, [string]$Destino)
    $info = New-Object System.IO.FileInfo -ArgumentList (Get-RutaLarga $Origen)
    if ($info.Length -gt 50MB) { throw 'AES no disponible y el archivo supera 50 MB para el modo XOR.' }
    $datos = [System.IO.File]::ReadAllBytes((Get-RutaLarga $Origen))
    for ($i = 0; $i -lt $datos.Length; $i++) { $datos[$i] = $datos[$i] -bxor 0x5A }
    $magia = [System.Text.Encoding]::ASCII.GetBytes('CUARX')
    $fs = New-Object System.IO.FileStream -ArgumentList $Destino, ([System.IO.FileMode]::CreateNew), ([System.IO.FileAccess]::Write)
    try { $fs.Write($magia, 0, 5); $fs.Write($datos, 0, $datos.Length) } finally { $fs.Dispose() }
    return 'XOR'
}

# ---------------------------------------------------------------------------
# Ejecutar programas nativos de forma segura (sin que stderr aborte el script)
# ---------------------------------------------------------------------------
function Resolve-ProgramaSistema {
    # Ruta absoluta para las herramientas de Windows: evita que un ejecutable
    # con el mismo nombre en otra carpeta del PATH se ejecute en su lugar.
    param([string]$Programa)
    if ($Programa -match '[\\/]') { return $Programa }
    if ($Programa -ieq 'powershell.exe') {
        $ps = Join-Path $PSHOME 'powershell.exe'
        if (Test-Path -LiteralPath $ps) { return $ps }
    }
    $p = Join-Path $env:SystemRoot ('System32\' + $Programa)
    if (Test-Path -LiteralPath $p) { return $p }
    return $Programa
}

function Read-Secreto {
    # Lee un secreto sin mostrarlo ni dejarlo en la transcripción (consola.txt)
    param([string]$Pregunta)
    $ss = Read-Host -Prompt $Pregunta -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $ss.Dispose() }
}

function Set-MarcaInternet {
    <#
      Añade la "Marca de la Web" (Zone.Identifier, zona 3 = Internet) a una
      copia del respaldo. En el PC sano, Windows tratará el archivo como
      descargado: SmartScreen revisa los ejecutables y Office abre los
      documentos en Vista protegida (macros bloqueadas). No altera el contenido.
    #>
    param([string]$Ruta)
    $texto = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=about:usb-forense`r`n"
    Set-Content -LiteralPath $Ruta -Stream 'Zone.Identifier' -Value $texto -Encoding Ascii -NoNewline -ErrorAction Stop
}

function Get-HashesAncla {
    # Manifiesto de confianza incrustado en boot.wim (X:\Ancla). Clave = ruta relativa en minúsculas.
    $res = @{}
    $m = Join-Path $env:SystemDrive 'Ancla\manifest.sha256'
    if (-not (Test-Path -LiteralPath $m)) { return $res }
    foreach ($l in [System.IO.File]::ReadAllLines($m, [System.Text.Encoding]::UTF8)) {
        if ($l -match '^([0-9A-Fa-f]{64})\s+(.+)$') { $res[$Matches[2].Trim().ToLowerInvariant()] = $Matches[1].ToUpperInvariant() }
    }
    return $res
}

function Test-ArchivosContraAncla {
    <#
      Comprueba, justo antes de ejecutarlos, que los binarios del USB (ClamAV,
      smartctl) siguen siendo los sellados en el ancla. Devuelve la lista de
      problemas (vacía = correcto).
    #>
    param([string]$RutaHerramientas, [string]$Prefijo)
    $problemas = [System.Collections.Generic.List[string]]::new()
    $ancla = Get-HashesAncla
    if ($ancla.Count -eq 0) { $problemas.Add('No hay manifiesto ancla en X:\Ancla (¿fuera de WinPE?).'); return , $problemas }
    $pref = $Prefijo.ToLowerInvariant()
    $base = $RutaHerramientas.Substring(0, 2) + '\'
    $n = 0
    foreach ($k in $ancla.Keys) {
        if (-not $k.StartsWith($pref)) { continue }
        $n++
        $ruta = $base + $k
        if (-not [System.IO.File]::Exists($ruta)) { $problemas.Add("FALTA: $k"); continue }
        try { if ((Get-Sha256Archivo -Ruta $ruta).Hash -ne $ancla[$k]) { $problemas.Add("MODIFICADO: $k") } }
        catch { $problemas.Add("ILEGIBLE: $k") }
    }
    if ($n -eq 0) { $problemas.Add("El ancla no contiene archivos bajo $Prefijo") }
    # Ningún ejecutable o DLL extra junto a los sellados (secuestro de DLL)
    $dir = $base + $Prefijo.TrimEnd('\')
    if (Test-Path -LiteralPath $dir) {
        foreach ($f in [System.IO.Directory]::GetFiles($dir)) {
            $rel = $f.Substring($base.Length).ToLowerInvariant()
            if ($rel -match '\.(exe|dll|sys|cpl|ocx|bat|cmd|ps1)$' -and -not $ancla.ContainsKey($rel)) { $problemas.Add("SOBRANTE: $rel") }
        }
    }
    return , $problemas
}

function Invoke-Nativo {
    param(
        [Parameter(Mandatory = $true)][string]$Programa,
        [string[]]$Argumentos = @(),
        [string]$ArchivoSalida,
        [switch]$Mostrar
    )
    $Programa = Resolve-ProgramaSistema $Programa
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = -999
    $salida = @()
    try {
        $salida = @(& $Programa @Argumentos 2>&1 | ForEach-Object { [string]$_ })
    } catch {
        $salida = @("No se pudo ejecutar ${Programa}: $($_.Exception.Message)")
    } finally {
        $ErrorActionPreference = $eap
    }
    $codigo = $global:LASTEXITCODE
    if ($ArchivoSalida) {
        try { [System.IO.File]::WriteAllLines($ArchivoSalida, [string[]]$salida, $script:Utf8ConBom) } catch { }
    }
    if ($Mostrar) { foreach ($l in $salida) { Write-Host $l } }
    return [pscustomobject]@{ Codigo = $codigo; Salida = $salida }
}

# Ejecuta un programa nativo mostrando su salida en vivo (procesos largos).
function Invoke-NativoEnVivo {
    param([Parameter(Mandatory = $true)][string]$Programa, [string[]]$Argumentos = @())
    $Programa = Resolve-ProgramaSistema $Programa
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = -999
    try {
        & $Programa @Argumentos 2>&1 | ForEach-Object { Write-Host ([string]$_) }
    } catch {
        Write-Log ("No se pudo ejecutar {0}: {1}" -f $Programa, $_.Exception.Message) -Nivel ERROR
    } finally {
        $ErrorActionPreference = $eap
    }
    return $global:LASTEXITCODE
}

function Get-EspacioLibre {
    param([string]$Letra)
    $d = New-Object System.IO.DriveInfo -ArgumentList ($Letra.Substring(0, 1))
    return [int64]$d.AvailableFreeSpace
}

function ConvertTo-HtmlSeguro {
    # Escapa texto proveniente del equipo analizado antes de ponerlo en HTML
    param($Texto)
    if ($null -eq $Texto) { return '' }
    return [System.Net.WebUtility]::HtmlEncode((ConvertTo-TextoSeguro $Texto))
}

function Get-NombreSeguro {
    # Convierte una ruta en un nombre de carpeta válido y corto
    param([string]$Texto, [int]$Max = 80)
    $s = $Texto -replace '^[A-Za-z]:\\', '' -replace '[\\/:*?"<>|]', '_' -replace '\s+', ' '
    $s = $s.Trim(' ', '.', '_')
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) }
    if ($s -eq '') { $s = 'raiz' }
    return $s
}

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
