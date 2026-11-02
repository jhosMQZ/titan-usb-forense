<#
    Persistencia.ps1 - Análisis de persistencia SIN CONEXIÓN.
    Lee COPIAS de los hives del registro (SOFTWARE, SYSTEM, NTUSER.DAT) hechas
    en la carpeta de trabajo del USB: los originales nunca se cargan ni se tocan.

    Revisa: carpetas de Inicio, claves Run/RunOnce, Winlogon, AppInit_DLLs,
    IFEO, LSA, BootExecute, tareas programadas (XML + TaskCache) y
    servicios/controladores. Asigna puntuación de riesgo y severidad.
#>

$script:HivesCargados = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# Hives offline
# ---------------------------------------------------------------------------
function Mount-HiveOffline {
    param([string]$Origen, [string]$Nombre, [string]$CarpetaTrabajo)
    $dirOrigen = Split-Path -Path $Origen -Parent
    $base = Split-Path -Path $Origen -Leaf
    $destDir = Join-Path $CarpetaTrabajo ('hives\' + $Nombre)
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    foreach ($suf in @('', '.LOG1', '.LOG2')) {
        $src = Join-Path $dirOrigen ($base + $suf)
        if ([System.IO.File]::Exists($src)) {
            $dst = Join-Path $destDir ($base + $suf)
            [System.IO.File]::Copy($src, $dst, $true)
            [System.IO.File]::SetAttributes($dst, [System.IO.FileAttributes]::Normal)
        }
    }
    $copia = Join-Path $destDir $base
    if (-not [System.IO.File]::Exists($copia)) { throw "No existe el hive $Origen" }
    [void](Invoke-Nativo 'reg.exe' @('unload', "HKLM\$Nombre"))   # por si quedó de una ejecución anterior
    $r = Invoke-Nativo 'reg.exe' @('load', "HKLM\$Nombre", $copia)
    if ($r.Codigo -ne 0) { throw ("reg load falló para {0}: {1}" -f $Origen, ($r.Salida -join ' ')) }
    $script:HivesCargados.Add($Nombre)
    Write-Log ("Hive (copia) cargado: {0} -> HKLM\{1}" -f $Origen, $Nombre) -SoloArchivo
}

function Dismount-HivesOffline {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    foreach ($n in $script:HivesCargados.ToArray()) {
        $ok = $false
        for ($i = 0; $i -lt 5; $i++) {
            $r = Invoke-Nativo 'reg.exe' @('unload', "HKLM\$n")
            if ($r.Codigo -eq 0) { $ok = $true; break }
            Start-Sleep -Seconds 2
            [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        }
        if (-not $ok) { Write-Log ("No se pudo descargar HKLM\{0} (se libera al reiniciar WinPE)." -f $n) -Nivel AVISO }
    }
    $script:HivesCargados.Clear()
}

function Get-ValoresClave {
    param([string]$Ruta)
    $k = $null
    try { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Ruta, $false) } catch { return }
    if ($null -eq $k) { return }
    try {
        foreach ($n in $k.GetValueNames()) {
            $v = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($v -is [byte[]]) { $v = '(binario {0} bytes)' -f $v.Length }
            elseif ($v -is [array]) { $v = (@($v) | ForEach-Object { [string]$_ }) -join '; ' }
            [pscustomobject]@{ Nombre = $n; Valor = [string]$v }
        }
    } finally { $k.Close() }
}

function Get-ValorClave {
    param([string]$Ruta, [string]$Nombre)
    $k = $null
    try { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Ruta, $false) } catch { return $null }
    if ($null -eq $k) { return $null }
    try {
        $v = $k.GetValue($Nombre, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($v -is [byte[]]) { return $v }
        if ($v -is [array]) { return ((@($v) | ForEach-Object { [string]$_ }) -join '; ') }
        return $v
    } finally { $k.Close() }
}

function Get-SubclavesClave {
    param([string]$Ruta)
    $k = $null
    try { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Ruta, $false) } catch { return @() }
    if ($null -eq $k) { return @() }
    try { return @($k.GetSubKeyNames()) } finally { $k.Close() }
}

# ---------------------------------------------------------------------------
# Lectura segura de formatos controlados por el atacante
# ---------------------------------------------------------------------------
function Read-XmlSeguro {
    # XML sin DTD (bloquea "billion laughs" y entidades externas) y con límite de tamaño
    param([string]$Ruta)
    $xs = New-Object System.Xml.XmlReaderSettings
    $xs.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $xs.XmlResolver = $null
    $xs.MaxCharactersInDocument = 2000000
    $xs.IgnoreProcessingInstructions = $true
    $xr = [System.Xml.XmlReader]::Create($Ruta, $xs)
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($xr)
        return $doc
    } finally { $xr.Dispose() }
}

function Get-CadenaAnsiZ {
    param([byte[]]$B, [int64]$Inicio, [int64]$Fin)
    if ($Inicio -lt 0 -or $Fin -gt $B.Length -or $Inicio -ge $Fin) { return '' }
    $n = [Array]::IndexOf($B, [byte]0, [int]$Inicio, [int]($Fin - $Inicio))
    if ($n -lt 0) { $n = [int]$Fin }
    return [System.Text.Encoding]::Default.GetString($B, [int]$Inicio, [int]($n - $Inicio))
}

function Get-CadenaUnicodeZ {
    param([byte[]]$B, [int64]$Inicio, [int64]$Fin)
    if ($Inicio -lt 0 -or $Fin -gt $B.Length -or $Inicio -ge $Fin) { return '' }
    $i = $Inicio
    while ($i + 1 -lt $Fin -and -not ($B[$i] -eq 0 -and $B[$i + 1] -eq 0)) { $i += 2 }
    return [System.Text.Encoding]::Unicode.GetString($B, [int]$Inicio, [int]($i - $Inicio))
}

function Read-AccesoDirecto {
    <#
      Analizador mínimo y con comprobación de límites del formato .lnk
      (MS-SHLLINK). Extrae destino local y argumentos SIN usar el Shell de
      Windows (WScript.Shell / IShellLink), que es superficie de ataque.
    #>
    param([string]$Ruta)
    $res = [pscustomobject]@{ Valido = $false; Destino = ''; RutaRelativa = ''; Argumentos = '' }
    try {
        $fi = New-Object System.IO.FileInfo -ArgumentList (Get-RutaLarga $Ruta)
        if ($fi.Length -lt 0x4C -or $fi.Length -gt 1MB) { return $res }
        $b = [System.IO.File]::ReadAllBytes((Get-RutaLarga $Ruta))
        if ([System.BitConverter]::ToUInt32($b, 0) -ne 0x4C) { return $res }
        $flags = [System.BitConverter]::ToUInt32($b, 0x14)
        [int64]$pos = 0x4C
        if (($flags -band 0x1) -ne 0) {                       # HasLinkTargetIDList
            if ($pos + 2 -gt $b.Length) { return $res }
            $pos += 2 + [System.BitConverter]::ToUInt16($b, [int]$pos)
        }
        if (($flags -band 0x2) -ne 0) {                       # HasLinkInfo
            if ($pos + 0x1C -gt $b.Length) { return $res }
            $li = $pos
            $liTam = [int64][System.BitConverter]::ToUInt32($b, [int]$li)
            $liCab = [int64][System.BitConverter]::ToUInt32($b, [int]$li + 4)
            $liFlags = [System.BitConverter]::ToUInt32($b, [int]$li + 8)
            if ($liTam -lt 0x1C -or $li + $liTam -gt $b.Length) { return $res }
            $fin = $li + $liTam
            if (($liFlags -band 0x1) -ne 0) {                  # VolumeIDAndLocalBasePath
                $base = ''
                if ($liCab -ge 0x24 -and $li + 0x24 -le $b.Length) {
                    $offU = [int64][System.BitConverter]::ToUInt32($b, [int]$li + 0x1C)
                    if ($offU -gt 0) { $base = Get-CadenaUnicodeZ -B $b -Inicio ($li + $offU) -Fin $fin }
                }
                if (-not $base) {
                    $off = [int64][System.BitConverter]::ToUInt32($b, [int]$li + 0x10)
                    $base = Get-CadenaAnsiZ -B $b -Inicio ($li + $off) -Fin $fin
                }
                $offSuf = [int64][System.BitConverter]::ToUInt32($b, [int]$li + 0x18)
                $suf = Get-CadenaAnsiZ -B $b -Inicio ($li + $offSuf) -Fin $fin
                $res.Destino = $base + $suf
            }
            $pos = $fin
        }
        $unicode = (($flags -band 0x80) -ne 0)
        foreach ($campo in @(@(0x4, 'Nombre'), @(0x8, 'RutaRelativa'), @(0x10, 'Trabajo'), @(0x20, 'Argumentos'), @(0x40, 'Icono'))) {
            if (($flags -band $campo[0]) -eq 0) { continue }
            if ($pos + 2 -gt $b.Length) { break }
            $n = [int64][System.BitConverter]::ToUInt16($b, [int]$pos); $pos += 2
            $largo = $n
            if ($unicode) { $largo = $n * 2 }
            if ($pos + $largo -gt $b.Length) { break }
            $txt = ''
            if ($unicode) { $txt = [System.Text.Encoding]::Unicode.GetString($b, [int]$pos, [int]$largo) }
            else { $txt = [System.Text.Encoding]::Default.GetString($b, [int]$pos, [int]$largo) }
            $pos += $largo
            if ($campo[1] -eq 'Argumentos') { $res.Argumentos = $txt }
            elseif ($campo[1] -eq 'RutaRelativa') { $res.RutaRelativa = $txt }
        }
        $res.Valido = $true
    } catch { }
    return $res
}

# ---------------------------------------------------------------------------
# Contexto del sistema offline
# ---------------------------------------------------------------------------
function Get-InfoSistemaOffline {
    param([string]$VolWindows)
    $info = [ordered]@{
        Nombre = '(desconocido)'; Producto = ''; Version = ''; Build = ''
        ControlSet = 'ControlSet001'; LetraOriginal = 'C'; SystemRoot = 'C:\Windows'
    }
    $cur = Get-ValorClave 'OFF_SYSTEM\Select' 'Current'
    if ($cur) { $info.ControlSet = 'ControlSet{0:000}' -f [int]$cur }
    $n = Get-ValorClave ("OFF_SYSTEM\{0}\Control\ComputerName\ComputerName" -f $info.ControlSet) 'ComputerName'
    if ($n) { $info.Nombre = [string]$n }
    $cv = 'OFF_SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $info.Producto = [string](Get-ValorClave $cv 'ProductName')
    $info.Version = [string](Get-ValorClave $cv 'DisplayVersion')
    $info.Build = ('{0}.{1}' -f (Get-ValorClave $cv 'CurrentBuild'), (Get-ValorClave $cv 'UBR'))
    $sr = [string](Get-ValorClave $cv 'SystemRoot')
    if ($sr -match '^([A-Za-z]):\\') { $info.LetraOriginal = $Matches[1].ToUpperInvariant(); $info.SystemRoot = $sr }
    # Windows 11 se identifica como "Windows 10" en ProductName: se corrige por build
    $b = 0; [void][int]::TryParse([string](Get-ValorClave $cv 'CurrentBuild'), [ref]$b)
    if ($b -ge 22000 -and $info.Producto -match 'Windows 10') { $info.Producto = $info.Producto -replace 'Windows 10', 'Windows 11' }
    return [pscustomobject]$info
}

function Expand-RutaOffline {
    <#
      Traduce rutas del sistema analizado (variables de entorno, \SystemRoot,
      \??\, letra original C:) a rutas visibles en WinPE (p. ej. D:\...).
    #>
    param([string]$Texto, [string]$VolWindows, [string]$LetraOriginal = 'C', [string]$Perfil = $null)
    if ([string]::IsNullOrEmpty($Texto)) { return $Texto }
    $w = $VolWindows.TrimEnd('\')
    $t = $Texto.Trim()
    $t = $t -replace '^\\\?\?\\', ''
    # Letra original del sistema (normalmente C:) -> letra actual en WinPE.
    # Se hace PRIMERO, sobre el texto original: así no se vuelve a traducir una
    # ruta ya convertida (si el volumen analizado quedara en una ruta con "C:\").
    $t = [regex]::Replace($t, ('(?i)(?<![A-Za-z]){0}:\\' -f [regex]::Escape($LetraOriginal)), (($w + '\') -replace '\$', '$$$$'))
    $t = $t -replace '(?i)^\\SystemRoot\\', "$w\Windows\"
    $t = $t -replace '(?i)^(System32|SysWOW64)\\', "$w\Windows\`$1\"
    $map = [ordered]@{
        '%SystemRoot%'         = "$w\Windows"
        '%windir%'             = "$w\Windows"
        '%SystemDrive%'        = $w
        '%ProgramFiles(x86)%'  = "$w\Program Files (x86)"
        '%ProgramFiles%'       = "$w\Program Files"
        '%ProgramW6432%'       = "$w\Program Files"
        '%CommonProgramFiles(x86)%' = "$w\Program Files (x86)\Common Files"
        '%CommonProgramFiles%' = "$w\Program Files\Common Files"
        '%ProgramData%'        = "$w\ProgramData"
        '%ALLUSERSPROFILE%'    = "$w\ProgramData"
        '%PUBLIC%'             = "$w\Users\Public"
    }
    if ($Perfil) {
        $map['%USERPROFILE%'] = $Perfil
        $map['%APPDATA%'] = "$Perfil\AppData\Roaming"
        $map['%LOCALAPPDATA%'] = "$Perfil\AppData\Local"
        $map['%TEMP%'] = "$Perfil\AppData\Local\Temp"
        $map['%TMP%'] = "$Perfil\AppData\Local\Temp"
    } else {
        $map['%TEMP%'] = "$w\Windows\Temp"
        $map['%TMP%'] = "$w\Windows\Temp"
    }
    foreach ($k in $map.Keys) {
        $t = [regex]::Replace($t, [regex]::Escape($k), ($map[$k] -replace '\$', '$$$$'), 'IgnoreCase')
    }
    return $t
}

$script:RxRutas = New-Object System.Text.RegularExpressions.Regex -ArgumentList '(?i)([a-z]:\\[^"<>|*?\r\n]*?\.(?:exe|dll|sys|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|pif|cpl|ocx|msi|lnk|jar))(?=$|[\s"'',;])'

function Get-RutasEnComando {
    param([string]$Comando)
    $res = @()
    foreach ($m in $script:RxRutas.Matches($Comando)) { $res += $m.Groups[1].Value.Trim() }
    return $res
}

$script:NombresSistema = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'explorer.exe', 'spoolsv.exe', 'taskhost.exe', 'taskhostw.exe', 'dllhost.exe', 'conhost.exe', 'rundll32.exe', 'wininit.exe', 'lsm.exe', 'ctfmon.exe', 'sihost.exe', 'runtimebroker.exe', 'searchindexer.exe', 'audiodg.exe')
$script:PatronesComando = @(
    @{ Rx = '(?i)\s-(e|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[A-Za-z0-9+/=]{20,}'; P = 3; M = 'PowerShell con comando codificado' },
    @{ Rx = '(?i)(\biex\b|invoke-expression|downloadstring|downloadfile|frombase64string|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer)'; P = 3; M = 'Descarga/ejecución dinámica de código' },
    @{ Rx = '(?i)\bmshta(\.exe)?\b.*(https?:|javascript:|vbscript:)'; P = 3; M = 'mshta con contenido remoto o script' },
    @{ Rx = '(?i)\bregsvr32(\.exe)?\b.*\/i:\s*https?'; P = 3; M = 'regsvr32 con scriptlet remoto' },
    @{ Rx = '(?i)\brundll32(\.exe)?\b.*javascript:'; P = 3; M = 'rundll32 con javascript' },
    @{ Rx = '(?i)\bcertutil(\.exe)?\b.*(-urlcache|-decode)'; P = 3; M = 'certutil usado para descargar/decodificar' },
    @{ Rx = '(?i)\bbitsadmin(\.exe)?\b.*\/transfer'; P = 3; M = 'bitsadmin descargando archivos' },
    @{ Rx = '(?i)https?://'; P = 2; M = 'URL en la línea de comandos' },
    @{ Rx = '(?i)\s-w(indowstyle)?\s+h(idden)?\b'; P = 1; M = 'Ventana oculta' }
)

function Measure-Ruta {
    # Puntuación de riesgo de una ruta de archivo ya traducida.
    param([string]$Ruta, [string]$VolWindows)
    $p = 0; $motivos = @()
    $w = [regex]::Escape($VolWindows.TrimEnd('\'))
    $r = $Ruta
    $estandar = @(
        "(?i)^$w\\Windows\\",
        "(?i)^$w\\Program Files\\",
        "(?i)^$w\\Program Files \(x86\)\\",
        "(?i)^$w\\ProgramData\\Microsoft\\",
        "(?i)^$w\\Users\\[^\\]+\\AppData\\Local\\Programs\\",
        "(?i)^$w\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\(OneDrive|Teams|WindowsApps|Edge)\\"
    )
    $esEstandar = $false
    foreach ($e in $estandar) { if ($r -match $e) { $esEstandar = $true; break } }
    $tipico = @(
        '(?i)\\AppData\\Local\\Temp\\', '(?i)\\Windows\\Temp\\', '(?i)\\\$Recycle\.Bin\\', '(?i)\\Users\\Public\\',
        '(?i)\\AppData\\Roaming\\[^\\]+$', '(?i)\\AppData\\Local\\[^\\]+$', "(?i)^$w\\ProgramData\\[^\\]+$",
        '(?i)\\Users\\[^\\]+\\(Downloads|Desktop|Documents|Music|Videos|Pictures)\\', '(?i)\\Windows\\Tasks\\'
    )
    $esTipico = $false
    foreach ($e in $tipico) { if ($r -match $e) { $esTipico = $true; break } }
    if ($esTipico) { $p += 3; $motivos += 'Ubicación típica de malware (temporal/usuario/raíz)' }
    elseif (-not $esEstandar -and $r -match '(?i)\\AppData\\') { $p += 2; $motivos += 'Carpeta de datos de usuario (AppData)' }
    elseif (-not $esEstandar) { $p += 1; $motivos += 'Fuera de las rutas de programas estándar' }

    $nombre = [System.IO.Path]::GetFileName($r).ToLowerInvariant()
    if ($script:NombresSistema -contains $nombre) {
        $enSuSitio = ($r -match "(?i)^$w\\Windows\\(System32|SysWOW64)\\[^\\]+$") -or
            ($r -match "(?i)^$w\\Windows\\[^\\]+$") -or ($r -match "(?i)^$w\\Windows\\WinSxS\\")
        if (-not $enSuSitio) { $p += 3; $motivos += 'Nombre de proceso del sistema fuera de su carpeta (suplantación)' }
    }
    if ($script:RxDobleExtension.IsMatch($nombre)) { $p += 3; $motivos += 'Doble extensión' }
    if ($nombre -match '\.(scr|pif|hta|vbs|vbe|js|jse|wsf)$') { $p += 1; $motivos += 'Tipo de archivo usado a menudo por malware' }
    if (-not (Test-ArchivoExiste $r)) { $p += 1; $motivos += 'El archivo referenciado no existe' }
    return [pscustomobject]@{ Puntos = $p; Motivos = $motivos }
}

function Get-Severidad {
    param([int]$Puntos)
    if ($Puntos -ge 4) { return 'Alta' }
    if ($Puntos -ge 2) { return 'Media' }
    if ($Puntos -ge 1) { return 'Baja' }
    return 'Info'
}

function New-HallazgoPersistencia {
    param(
        [string]$Categoria, [string]$Ubicacion, [string]$Nombre, [string]$Comando,
        [string]$VolWindows, [string]$LetraOriginal, [string]$Perfil = $null,
        [int]$PuntosExtra = 0, [string[]]$MotivosExtra = @(), [string]$RutaDirecta = $null
    )
    $exp = Expand-RutaOffline -Texto $Comando -VolWindows $VolWindows -LetraOriginal $LetraOriginal -Perfil $Perfil
    $puntos = $PuntosExtra
    $motivos = @() + $MotivosExtra
    foreach ($pc in $script:PatronesComando) {
        if ($exp -match $pc.Rx) { $puntos += $pc.P; $motivos += $pc.M }
    }
    $rutas = @()
    if ($RutaDirecta) { $rutas += $RutaDirecta } else { $rutas += Get-RutasEnComando $exp }
    $objetivos = @()
    $maxRuta = 0
    foreach ($r in $rutas) {
        $mr = Measure-Ruta -Ruta $r -VolWindows $VolWindows
        if ($mr.Puntos -gt $maxRuta) { $maxRuta = $mr.Puntos }
        $motivos += $mr.Motivos
        $objetivos += $r
    }
    $puntos += $maxRuta
    $motivos = @($motivos | Select-Object -Unique)
    return [pscustomobject]@{
        Categoria = $Categoria; Ubicacion = $Ubicacion; Nombre = $Nombre; Valor = $Comando
        RutasResueltas = ($objetivos -join ' | '); Objetivos = $objetivos
        Puntos = $puntos; Severidad = (Get-Severidad $puntos); Motivos = ($motivos -join '; ')
        Firma = ''; SHA256 = ''
    }
}

# ---------------------------------------------------------------------------
# Análisis principal
# ---------------------------------------------------------------------------
function Invoke-AnalisisPersistencia {
    param(
        [string]$VolWindows,
        $InfoSistema,
        $Perfiles,            # objetos {Nombre, Ruta, Hive}
        [string]$CarpetaDatos
    )
    $L = $InfoSistema.LetraOriginal
    $hall = [System.Collections.Generic.List[object]]::new()
    $sw = 'OFF_SOFTWARE'
    $cs = 'OFF_SYSTEM\' + $InfoSistema.ControlSet

    # 1) Claves Run de la máquina
    $runMaquina = @(
        'Microsoft\Windows\CurrentVersion\Run', 'Microsoft\Windows\CurrentVersion\RunOnce',
        'Microsoft\Windows\CurrentVersion\RunServices', 'Microsoft\Windows\CurrentVersion\RunServicesOnce',
        'WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($k in $runMaquina) {
        foreach ($v in @(Get-ValoresClave "$sw\$k")) {
            $hall.Add((New-HallazgoPersistencia -Categoria 'Registro Run (equipo)' -Ubicacion "HKLM\SOFTWARE\$k" -Nombre $v.Nombre -Comando $v.Valor -VolWindows $VolWindows -LetraOriginal $L))
        }
    }

    # 2) Winlogon, AppInit, IFEO, SilentProcessExit, LSA, BootExecute
    $wl = "$sw\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $shell = [string](Get-ValorClave $wl 'Shell')
    if ($shell -and $shell.Trim().ToLowerInvariant() -ne 'explorer.exe') {
        $hall.Add((New-HallazgoPersistencia -Categoria 'Winlogon' -Ubicacion 'HKLM\...\Winlogon' -Nombre 'Shell' -Comando $shell -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 4 -MotivosExtra @('Shell distinto de explorer.exe')))
    }
    $ui = [string](Get-ValorClave $wl 'Userinit')
    if ($ui -and $ui.Trim().TrimEnd(',').ToLowerInvariant() -notmatch '^([a-z]:\\windows\\system32\\)?userinit\.exe$') {
        $hall.Add((New-HallazgoPersistencia -Categoria 'Winlogon' -Ubicacion 'HKLM\...\Winlogon' -Nombre 'Userinit' -Comando $ui -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 4 -MotivosExtra @('Userinit modificado')))
    }
    foreach ($nv in @('Taskman', 'AppSetup')) {
        $x = [string](Get-ValorClave $wl $nv)
        if ($x) { $hall.Add((New-HallazgoPersistencia -Categoria 'Winlogon' -Ubicacion 'HKLM\...\Winlogon' -Nombre $nv -Comando $x -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 2 -MotivosExtra @("Valor $nv presente"))) }
    }
    foreach ($ntf in @(Get-SubclavesClave "$wl\Notify")) {
        $dll = [string](Get-ValorClave "$wl\Notify\$ntf" 'DLLName')
        if ($dll) { $hall.Add((New-HallazgoPersistencia -Categoria 'Winlogon Notify' -Ubicacion "HKLM\...\Winlogon\Notify\$ntf" -Nombre 'DLLName' -Comando $dll -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 2 -MotivosExtra @('DLL de notificación de Winlogon'))) }
    }
    foreach ($base in @("$sw\Microsoft\Windows NT\CurrentVersion\Windows", "$sw\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows")) {
        $ai = [string](Get-ValorClave $base 'AppInit_DLLs')
        if ($ai -and $ai.Trim() -ne '') {
            $hall.Add((New-HallazgoPersistencia -Categoria 'AppInit_DLLs' -Ubicacion $base.Replace('OFF_SOFTWARE', 'HKLM\SOFTWARE') -Nombre 'AppInit_DLLs' -Comando $ai -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 3 -MotivosExtra @('DLL inyectada en todos los procesos con interfaz')))
        }
    }
    $ifeo = "$sw\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    foreach ($ex in @(Get-SubclavesClave $ifeo)) {
        $dbg = [string](Get-ValorClave "$ifeo\$ex" 'Debugger')
        if ($dbg) { $hall.Add((New-HallazgoPersistencia -Categoria 'IFEO Debugger' -Ubicacion "HKLM\...\Image File Execution Options\$ex" -Nombre 'Debugger' -Comando $dbg -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 3 -MotivosExtra @("Secuestro del ejecutable $ex"))) }
    }
    $spe = "$sw\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
    foreach ($ex in @(Get-SubclavesClave $spe)) {
        $mp = [string](Get-ValorClave "$spe\$ex" 'MonitorProcess')
        if ($mp) { $hall.Add((New-HallazgoPersistencia -Categoria 'SilentProcessExit' -Ubicacion "HKLM\...\SilentProcessExit\$ex" -Nombre 'MonitorProcess' -Comando $mp -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 3 -MotivosExtra @("Se ejecuta al cerrar $ex"))) }
    }
    $be = [string](Get-ValorClave "$cs\Control\Session Manager" 'BootExecute')
    if ($be -and $be.Trim() -notmatch '^(?i)autocheck autochk[^;]*$') {
        $hall.Add((New-HallazgoPersistencia -Categoria 'BootExecute' -Ubicacion 'HKLM\SYSTEM\...\Session Manager' -Nombre 'BootExecute' -Comando $be -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 3 -MotivosExtra @('Programa adicional en el arranque nativo')))
    }
    $lsaConocidos = @('msv1_0', 'scecli', 'rassfm', 'kerberos', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', '""', '')
    foreach ($nv in @('Authentication Packages', 'Notification Packages', 'Security Packages')) {
        $val = [string](Get-ValorClave "$cs\Control\Lsa" $nv)
        foreach ($pk in ($val -split '[;\s]+')) {
            $pkl = $pk.Trim().ToLowerInvariant()
            if ($pkl -and -not ($lsaConocidos -contains $pkl)) {
                $hall.Add((New-HallazgoPersistencia -Categoria 'LSA' -Ubicacion 'HKLM\SYSTEM\...\Control\Lsa' -Nombre $nv -Comando $pk -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 3 -MotivosExtra @('Paquete LSA no estándar (puede capturar contraseñas)')))
            }
        }
    }

    # 3) Por usuario: Run, RunOnce, Load, Shell, script de inicio
    foreach ($pf in @($Perfiles)) {
        if (-not $pf.Hive) { continue }
        $h = $pf.Hive
        foreach ($k in @('Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')) {
            foreach ($v in @(Get-ValoresClave "$h\$k")) {
                $hall.Add((New-HallazgoPersistencia -Categoria ('Registro Run (usuario {0})' -f $pf.Nombre) -Ubicacion "HKCU\$k" -Nombre $v.Nombre -Comando $v.Valor -VolWindows $VolWindows -LetraOriginal $L -Perfil $pf.Ruta))
            }
        }
        foreach ($nv in @('Load', 'Run')) {
            $x = [string](Get-ValorClave "$h\Software\Microsoft\Windows NT\CurrentVersion\Windows" $nv)
            if ($x) { $hall.Add((New-HallazgoPersistencia -Categoria ('Windows Load/Run (usuario {0})' -f $pf.Nombre) -Ubicacion 'HKCU\...\Windows NT\CurrentVersion\Windows' -Nombre $nv -Comando $x -VolWindows $VolWindows -LetraOriginal $L -Perfil $pf.Ruta -PuntosExtra 2 -MotivosExtra @('Mecanismo de inicio heredado poco común'))) }
        }
        $us = [string](Get-ValorClave "$h\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 'Shell')
        if ($us) { $hall.Add((New-HallazgoPersistencia -Categoria ('Winlogon (usuario {0})' -f $pf.Nombre) -Ubicacion 'HKCU\...\Winlogon' -Nombre 'Shell' -Comando $us -VolWindows $VolWindows -LetraOriginal $L -Perfil $pf.Ruta -PuntosExtra 4 -MotivosExtra @('Shell de usuario reemplazado'))) }
        $mpr = [string](Get-ValorClave "$h\Environment" 'UserInitMprLogonScript')
        if ($mpr) { $hall.Add((New-HallazgoPersistencia -Categoria ('Script de inicio (usuario {0})' -f $pf.Nombre) -Ubicacion 'HKCU\Environment' -Nombre 'UserInitMprLogonScript' -Comando $mpr -VolWindows $VolWindows -LetraOriginal $L -Perfil $pf.Ruta -PuntosExtra 3 -MotivosExtra @('Script de inicio de sesión'))) }
    }

    # 4) Carpetas de Inicio (todos los usuarios + cada perfil)
    $carpetasInicio = @(@{ Ruta = "$VolWindows\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"; Perfil = $null; Nombre = 'Todos' })
    foreach ($pf in @($Perfiles)) {
        $carpetasInicio += @{ Ruta = "$($pf.Ruta)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"; Perfil = $pf.Ruta; Nombre = $pf.Nombre }
    }
    foreach ($ci in $carpetasInicio) {
        if (-not (Test-Path -LiteralPath $ci.Ruta)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $ci.Ruta -Force -File -ErrorAction SilentlyContinue)) {
            if ($f.Name -ieq 'desktop.ini') { continue }
            $cmd = $f.FullName
            $directa = $f.FullName
            $extra = 1; $mx = @('Se ejecuta al iniciar sesión')
            if ($f.Extension -ieq '.lnk') {
                # Analizador propio del formato .lnk (MS-SHLLINK): no usa el Shell
                # de Windows, así un acceso directo malicioso no toca código del sistema.
                $lk = Read-AccesoDirecto -Ruta $f.FullName
                if ($lk.Valido) {
                    $destino = $lk.Destino
                    if (-not $destino) { $destino = $lk.RutaRelativa }
                    $cmd = ('{0} {1}' -f $destino, $lk.Argumentos).Trim()
                    $directa = $null
                } else {
                    $extra += 2; $mx += 'Acceso directo dañado o con formato inusual'
                }
            }
            $hz = New-HallazgoPersistencia -Categoria ('Carpeta Inicio ({0})' -f $ci.Nombre) -Ubicacion $ci.Ruta -Nombre $f.Name -Comando $cmd -VolWindows $VolWindows -LetraOriginal $L -Perfil $ci.Perfil -RutaDirecta $directa -PuntosExtra $extra -MotivosExtra $mx
            $hall.Add($hz)
        }
    }

    # 5) Tareas programadas: XML en System32\Tasks + coherencia con TaskCache
    $dirTareas = "$VolWindows\Windows\System32\Tasks"
    $tareasXml = @{}
    if (Test-Path -LiteralPath $dirTareas) {
        foreach ($f in @(Get-ChildItem -LiteralPath $dirTareas -Recurse -Force -File -ErrorAction SilentlyContinue)) {
            $rel = $f.FullName.Substring($dirTareas.Length)
            $tareasXml[$rel.ToLowerInvariant()] = $true
            $esMicrosoft = $rel -match '(?i)^\\Microsoft\\'
            try {
                if ($f.Length -gt 1MB) { throw 'Archivo de tarea anormalmente grande (más de 1 MB)' }
                $doc = Read-XmlSeguro -Ruta $f.FullName
                $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
                $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
                $oculta = $doc.SelectSingleNode('//t:Settings/t:Hidden', $ns)
                $extra = 0; $mx = @()
                if ($oculta -and $oculta.InnerText -eq 'true' -and -not $esMicrosoft) { $extra += 1; $mx += 'Tarea marcada como oculta' }
                foreach ($ac in @($doc.SelectNodes('//t:Actions/t:Exec', $ns))) {
                    $c = $ac.SelectSingleNode('t:Command', $ns); $a = $ac.SelectSingleNode('t:Arguments', $ns)
                    $cmd = ''
                    if ($c) { $cmd = $c.InnerText }
                    if ($a) { $cmd = $cmd + ' ' + $a.InnerText }
                    $hz = New-HallazgoPersistencia -Categoria 'Tarea programada' -Ubicacion ('Tasks' + $rel) -Nombre $f.Name -Comando $cmd -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra $extra -MotivosExtra $mx
                    if (-not $esMicrosoft -or $hz.Puntos -ge 1) { $hall.Add($hz) }
                }
                foreach ($ch in @($doc.SelectNodes('//t:Actions/t:ComHandler', $ns))) {
                    $id = $ch.SelectSingleNode('t:ClassId', $ns)
                    if ($null -eq $id) { continue }
                    $clsid = $id.InnerText.Trim()
                    # Algunos programas (p. ej. McAfee) guardan el GUID sin llaves: es válido
                    if ($clsid -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$') { $clsid = '{' + $clsid + '}' }
                    if ($clsid -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
                        $hall.Add((New-HallazgoPersistencia -Categoria 'Tarea programada (COM)' -Ubicacion ('Tasks' + $rel) -Nombre $f.Name -Comando $clsid -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 3 -MotivosExtra @('ClassId con formato no válido')))
                        continue
                    }
                    $dll = [string](Get-ValorClave ("$sw\Classes\CLSID\{0}\InprocServer32" -f $clsid) '')
                    $hz = New-HallazgoPersistencia -Categoria 'Tarea programada (COM)' -Ubicacion ('Tasks' + $rel) -Nombre $f.Name -Comando $dll -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra $extra -MotivosExtra $mx
                    if (-not $esMicrosoft -or $hz.Puntos -ge 1) { $hall.Add($hz) }
                }
            } catch {
                Add-RegistroError -Fase 'Persistencia' -Ruta $f.FullName -Mensaje ('XML de tarea ilegible: ' + $_.Exception.Message) -Silencioso
                if (-not $esMicrosoft) {
                    $hall.Add((New-HallazgoPersistencia -Categoria 'Tarea programada' -Ubicacion ('Tasks' + $rel) -Nombre $f.Name -Comando '' -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra 2 -MotivosExtra @('XML de tarea dañado o manipulado') -RutaDirecta $f.FullName))
                }
            }
        }
    }
    $tree = "$sw\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
    $pend = [System.Collections.Generic.Stack[string]]::new()
    $pend.Push('')
    while ($pend.Count -gt 0) {
        $rel = $pend.Pop()
        foreach ($sub in @(Get-SubclavesClave ($tree + $rel))) {
            $r2 = "$rel\$sub"
            $id = Get-ValorClave ($tree + $r2) 'Id'
            if ($id) {
                $sd = Get-ValorClave ($tree + $r2) 'SD'
                if ($null -eq $sd) {
                    $hall.Add([pscustomobject]@{ Categoria = 'Tarea programada (registro)'; Ubicacion = 'TaskCache\Tree' + $r2; Nombre = $sub; Valor = ''; RutasResueltas = ''; Objetivos = @(); Puntos = 4; Severidad = 'Alta'; Motivos = 'Tarea sin descriptor de seguridad (técnica de ocultamiento tipo Tarrask)'; Firma = ''; SHA256 = '' })
                }
                if (-not $tareasXml.ContainsKey($r2.ToLowerInvariant())) {
                    $hall.Add([pscustomobject]@{ Categoria = 'Tarea programada (registro)'; Ubicacion = 'TaskCache\Tree' + $r2; Nombre = $sub; Valor = ''; RutasResueltas = ''; Objetivos = @(); Puntos = 2; Severidad = 'Media'; Motivos = 'Tarea registrada sin archivo XML (posible ocultamiento o residuo)'; Firma = ''; SHA256 = '' })
                }
            }
            $pend.Push($r2)
        }
    }

    # 6) Servicios y controladores
    $svcBase = "$cs\Services"
    foreach ($svc in @(Get-SubclavesClave $svcBase)) {
        $k = "$svcBase\$svc"
        $tipo = Get-ValorClave $k 'Type'
        $inicio = Get-ValorClave $k 'Start'
        if ($null -eq $tipo -or $null -eq $inicio) { continue }
        $tipo = [int]$tipo; $inicio = [int]$inicio
        if ($inicio -eq 4) { continue }                                   # deshabilitado
        $img = [string](Get-ValorClave $k 'ImagePath')
        $esDriver = (($tipo -band 0x3) -ne 0)
        if (-not $img -and $esDriver) { $img = "System32\drivers\$svc.sys" }
        if (-not $img) { continue }
        $extra = 0; $mx = @()
        $exp = Expand-RutaOffline -Texto $img -VolWindows $VolWindows -LetraOriginal $L
        if ($esDriver -and $exp -notmatch '(?i)\\Windows\\System32\\(drivers|DriverStore)\\') { $extra += 2; $mx += 'Controlador fuera de System32\drivers' }
        $sdll = [string](Get-ValorClave "$k\Parameters" 'ServiceDll')
        if ($sdll) {
            $sdllExp = Expand-RutaOffline -Texto $sdll -VolWindows $VolWindows -LetraOriginal $L
            if ($sdllExp -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\') { $extra += 2; $mx += 'ServiceDll fuera de System32' }
            $img = "$img  [ServiceDll: $sdll]"
        }
        $cat = 'Servicio'
        if ($esDriver) { $cat = 'Controlador' }
        $hz = New-HallazgoPersistencia -Categoria $cat -Ubicacion "HKLM\SYSTEM\...\Services\$svc" -Nombre $svc -Comando $img -VolWindows $VolWindows -LetraOriginal $L -PuntosExtra $extra -MotivosExtra $mx
        if ($hz.Puntos -ge 1) { $hall.Add($hz) }
    }

    # 7) Firma digital y hash de los objetivos con severidad Media/Alta
    foreach ($hz in $hall) {
        if (@('Alta', 'Media') -notcontains $hz.Severidad) { continue }
        $firmas = @(); $hashes = @()
        foreach ($o in @($hz.Objetivos)) {
            if (-not (Test-ArchivoExiste $o)) { continue }
            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $o -ErrorAction Stop
                $sujeto = ''
                if ($sig.SignerCertificate) { $sujeto = $sig.SignerCertificate.Subject }
                $firmas += ('{0} {1}' -f $sig.Status, $sujeto).Trim()
            } catch { $firmas += 'No verificable en WinPE' }
            try { $hashes += (Get-Sha256Archivo -Ruta $o).Hash } catch { }
        }
        $hz.Firma = $firmas -join ' | '
        $hz.SHA256 = $hashes -join ' | '
    }

    # Orden: severidad y puntos
    $ordenSev = @{ 'Alta' = 0; 'Media' = 1; 'Baja' = 2; 'Info' = 3 }
    $ordenados = @($hall | Sort-Object @{ Expression = { $ordenSev[$_.Severidad] } }, @{ Expression = { $_.Puntos }; Descending = $true })
    Export-ListaCsv -Ruta (Join-Path $CarpetaDatos 'persistencia.csv') -Objetos $ordenados -Columnas @('Severidad', 'Puntos', 'Categoria', 'Ubicacion', 'Nombre', 'Valor', 'RutasResueltas', 'Motivos', 'Firma', 'SHA256')
    return $ordenados
}
