#Requires -RunAsAdministrator
<#
    Probar-Blackbox.ps1 - Pruebas reproducibles de TITAN BLACKBOX en ESTE PC.

    Todo lo destructivo ocurre en DISCOS VIRTUALES desechables (VHDX en
    C:\TITAN_PRUEBA_BB_xxxx) que se crean, se usan y se borran. Nunca se elige
    un disco real: cada disco de prueba se identifica como el disco NUEVO que
    aparece al conectar su VHDX, y se comprueba su tamaño antes de usarlo.

    Casos del pliego cubiertos (ver el resumen al final de prueba_blackbox.txt).
#>
$ErrorActionPreference = 'Stop'
$aqui = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$repo = Split-Path -Path $aqui -Parent
$scripts = Join-Path $repo 'Herramientas\Scripts'
$salida = Join-Path $repo 'prueba_blackbox.txt'
try { Start-Transcript -Path $salida -Force | Out-Null } catch { }
foreach ($n in @('Comun', 'Disco', 'Malware', 'Persistencia', 'Respaldo', 'Reporte', 'Blackbox')) { . (Join-Path $scripts ('Lib\' + $n + '.ps1')) }
Initialize-RutasLargas

$script:Resultados = [System.Collections.Generic.List[object]]::new()
function Assert-Prueba {
    param([string]$Caso, [string]$Nombre, [bool]$Cond, $Detalle = '')
    $script:Resultados.Add([pscustomobject]@{ Caso = $Caso; Nombre = $Nombre; Ok = $Cond; Detalle = [string]$Detalle })
    if ($Cond) { Write-Host ('  OK    [{0}] {1}' -f $Caso, $Nombre) -ForegroundColor Green }
    else { Write-Host ('  FALLO [{0}] {1} :: {2}' -f $Caso, $Nombre, $Detalle) -ForegroundColor Red }
}
function Write-Seccion {
    param([string]$T)
    Write-Host ''
    Write-Host ('=== ' + $T + ' ===') -ForegroundColor Cyan
}

$id = [guid]::NewGuid().ToString('N').Substring(0, 6)
$tmp = Join-Path ($env:SystemDrive + '\') ('TITAN_PRUEBA_BB_' + $id)
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
Initialize-Registro -ArchivoLog (Join-Path $tmp 'prueba.log')
$discosPrueba = [System.Collections.Generic.List[object]]::new()
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function New-Aleatorio {
    param([int]$N)
    $b = New-Object byte[] $N
    $rng.GetBytes($b)
    return , $b
}

function New-VhdPrueba {
    <# Crea, conecta y particiona un VHDX desechable. Devuelve número de disco y letras. #>
    param([string]$Nombre, [int]$TamMB, [object[]]$Particiones)
    $ruta = Join-Path $tmp ($Nombre + '.vhdx')
    $antes = @(Get-ListaDiscosDp | ForEach-Object { $_.Number })
    [void](Invoke-Diskpart @(('create vdisk file="{0}" maximum={1} type=expandable' -f $ruta, $TamMB), ('select vdisk file="{0}"' -f $ruta), 'attach vdisk'))
    Start-Sleep -Seconds 3
    $nuevos = @(Get-ListaDiscosDp | Where-Object { $antes -notcontains $_.Number })
    if ($nuevos.Count -ne 1) { throw "No se identificó el disco nuevo de $Nombre" }
    $n = [int]$nuevos[0].Number
    $tam = ConvertFrom-TamanoDiskpart $nuevos[0].Tamano
    if ($n -eq 0 -or $tam -lt ($TamMB - 64) * 1MB -or $tam -gt ($TamMB + 64) * 1MB) { throw "Disco de prueba inesperado (#$n, $($nuevos[0].Tamano)): se cancela por seguridad." }
    $discosPrueba.Add([pscustomobject]@{ Ruta = $ruta; Disco = $n })
    $cmd = @("select disk $n", 'convert mbr noerr')
    foreach ($p in $Particiones) {
        if ($p.TamMB -gt 0) { $cmd += ('create partition primary size={0}' -f $p.TamMB) } else { $cmd += 'create partition primary' }
        if ($p.Fs -ne 'raw') { $cmd += ('format fs={0} quick label={1}' -f $p.Fs, $p.Etiqueta) }
        $cmd += 'assign'
    }
    $r = Invoke-Diskpart $cmd
    Start-Sleep -Seconds 3
    $letras = @((Get-DetalleDiscoDp -Numero $n).Volumenes | Sort-Object Num | ForEach-Object { if ($_.Letra) { $_.Letra + ':' } else { '' } })
    return [pscustomobject]@{ Disco = $n; Letras = $letras; Ruta = $ruta; Salida = ($r -join ' | ') }
}

function Invoke-Blackbox {
    param([string]$Nombre, [string[]]$Argumentos)
    $log = Join-Path $tmp ('blackbox_' + $Nombre + '.txt')
    $ps = Join-Path $PSHOME 'powershell.exe'
    $todos = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $scripts 'Blackbox.ps1'),
        '-RutaHerramientas', (Join-Path $repo 'Herramientas'), '-PermitirFueraDeWinPE', '-RutaMotor', $script:RutaMotor, '-Automatico') + $Argumentos
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $texto = & $ps @todos 2>&1 | ForEach-Object { [string]$_ }
    $codigo = $LASTEXITCODE
    $ErrorActionPreference = $eap
    [System.IO.File]::WriteAllLines($log, [string[]]$texto, $script:Utf8ConBom)
    $caso = ''
    foreach ($l in $texto) { if ($l -match 'Trabajo guardado en:\s*(.+)$') { $caso = $Matches[1].Trim() } }
    foreach ($l in ($texto | Select-Object -Last 12)) { Write-Host ('    | ' + $l) -ForegroundColor DarkGray }
    return [pscustomobject]@{ Codigo = $codigo; Caso = $caso; Texto = ($texto -join "`n"); Log = $log }
}

function Get-Resultados {
    param([string]$Caso)
    $csv = Join-Path $Caso 'Datos\resultado_archivos.csv'
    if (-not (Test-Path -LiteralPath $csv)) { return @() }
    return @(Import-Csv -LiteralPath $csv -Delimiter ';' -Encoding UTF8)
}
function Find-Fila {
    # EndsWith (no -like): los nombres de prueba llevan corchetes y otros comodines
    param($Filas, [string]$Fin)
    return ($Filas | Where-Object { ([string]$_.Ruta).EndsWith('\' + $Fin, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)
}
function Get-EntradasDiario {
    param([string]$Caso, [string]$IdArchivo)
    $l = [System.IO.File]::ReadAllLines((Join-Path $Caso 'Datos\diario.tsv'), [System.Text.Encoding]::UTF8)
    return @($l | Where-Object { $_.Split("`t")[1] -eq $IdArchivo })
}
function Get-Hash {
    param([string]$R)
    return (Get-Sha256Archivo -Ruta $R).Hash
}

$originales = @{}
try {
    # =======================================================================
    Write-Seccion '0. Motor: compilación y arranque'
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $c = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $aqui 'Compilar-Rescate.ps1') 2>&1 | ForEach-Object { [string]$_ }
    $ErrorActionPreference = $eap
    $c | ForEach-Object { Write-Host ('    | ' + $_) }
    $script:RutaMotor = Join-Path $repo 'Herramientas\Blackbox\TitanRescate.exe'
    Assert-Prueba 'Herramientas' 'TitanRescate.exe compilado con el csc de Windows' (Test-Path -LiteralPath $script:RutaMotor)
    $v = Invoke-Motor -Argumentos @('version')
    Assert-Prueba 'Herramientas' 'El motor arranca en 64 bits' ($v.estado -eq 'OK' -and $v.x64) ($v | ConvertTo-Json -Compress)
    $s0 = Invoke-Motor -Argumentos @('salud', '--disco', '0')
    Assert-Prueba 'Herramientas' 'Salud del disco 0 sin escribir (NVMe o predicción de fallo)' ($s0.estado -eq 'OK' -and $s0.veredicto) ($s0 | ConvertTo-Json -Compress)
    Write-Host ('    disco 0: bus {0} | {1} | veredicto {2} | fuente {3} | desgaste {4}% | horas {5}' -f $s0.bus, $s0.modelo, $s0.veredicto, $s0.fuente, $s0.desgastePct, $s0.horasEncendido)
    $smartctl = Join-Path $repo 'Herramientas\Smartmontools\smartctl.exe'
    Write-Host ('    smartctl.exe presente: {0} (opcional; el motor lee la salud NVMe por sí mismo)' -f (Test-Path -LiteralPath $smartctl))

    # =======================================================================
    Write-Seccion '1. BitLocker: lectura del estado (casos simulados de manage-bde)'
    $original = ${function:Invoke-Nativo}
    $casosBde = @(
        @('Lock Status:          Locked', 'Bloqueado'),
        @("Conversion Status:    Fully Decrypted`nLock Status:          Unlocked", 'SinBitLocker'),
        @("Conversion Status:    Used Space Only Encrypted`nLock Status:          Unlocked", 'Desbloqueado'),
        @('Estado de bloqueo:    Bloqueado', 'Bloqueado'),
        @('ERROR: The volume Z: could not be opened by BitLocker. This may be because the volume does not exist, or because it is not a valid BitLocker volume.', 'SinBitLocker')
    )
    foreach ($cb in $casosBde) {
        $script:SalidaBde = $cb[0]
        Set-Item -Path function:Invoke-Nativo -Value {
            param($Programa, $Argumentos)
            [pscustomobject]@{ Codigo = 0; Salida = @($script:SalidaBde -split "`n") }
        }
        $e = Get-EstadoBitLocker -Letra 'Z:'
        Assert-Prueba 'BitLocker' ('manage-bde "{0}..." -> {1}' -f $cb[0].Substring(0, [Math]::Min(30, $cb[0].Length)), $cb[1]) ($e -eq $cb[1]) $e
    }
    Set-Item -Path function:Invoke-Nativo -Value $original
    Write-Host '    (No se puede crear un volumen BitLocker de prueba: Windows 11 Home no permite activar BitLocker.)' -ForegroundColor Yellow

    # =======================================================================
    Write-Seccion '2. Cola: archivo en uso (reencolado, error repetido) y reanudación'
    $dirCola = Join-Path $tmp 'cola'
    New-Item -ItemType Directory -Path "$dirCola\origen" -Force | Out-Null
    [System.IO.File]::WriteAllBytes("$dirCola\origen\libre.txt", (New-Aleatorio 5000))
    [System.IO.File]::WriteAllBytes("$dirCola\origen\en_uso.txt", (New-Aleatorio 7000))
    $hEnUso = Get-Hash "$dirCola\origen\en_uso.txt"
    $cfgB = (Get-Content -LiteralPath (Join-Path $scripts 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json).Blackbox
    $cfgB.MargenLibreMB = 1; $cfgB.EsperaMs = 10
    $dirsCola = New-TrabajoBlackbox -Caso "$dirCola\caso" -Identidad $null
    $mk = {
        param($n)
        [pscustomobject]@{ Id = (Get-IdArchivo -Serie 'X' -Relativa $n); Ruta = "$dirCola\origen\$n"; Relativa = $n; Serie = 'X'; Carpeta = 'Prueba'; RelCarpeta = $n
            Tamano = (Get-Item -LiteralPath "$dirCola\origen\$n").Length; Modificado = ''; Prioridad = 1; Categoria = 'Documentos'; Estado = 'PENDIENTE'; Motivo = ''; Intentos = 0; UltimoCodigo = -1; Destino = ''; Resultado = $null; Pasada = 1 }
    }
    $bloqueo = [System.IO.File]::Open("$dirCola\origen\en_uso.txt", 'Open', 'Read', 'None')
    try {
        $cola = @((& $mk 'libre.txt'), (& $mk 'en_uso.txt'))
        [void](Invoke-ColaRecuperacion -Cola $cola -Dirs $dirsCola -Config $cfgB -Destino $dirCola)
    } finally { $bloqueo.Dispose() }
    Assert-Prueba 'Inaccesible' 'Archivo libre copiado íntegro' ($cola[0].Estado -eq 'RECUPERADO_INTEGRO') $cola[0].Estado
    Assert-Prueba 'Inaccesible' 'Archivo en uso: ARCHIVO_INACCESIBLE tras reencolar una vez (error repetido detectado)' ($cola[1].Estado -eq 'ERROR_RECUPERACION' -and $cola[1].Motivo -like 'ARCHIVO_INACCESIBLE*' -and $cola[1].Intentos -eq 2) ('{0} | {1} | intentos {2}' -f $cola[1].Estado, $cola[1].Motivo, $cola[1].Intentos)
    $cola2 = @((& $mk 'libre.txt'), (& $mk 'en_uso.txt'))
    $rr = Restore-EstadoDesdeDiario -Cola $cola2 -RutaDiario (Join-Path $dirsCola.Datos 'diario.tsv') -Dirs $dirsCola
    [void](Invoke-ColaRecuperacion -Cola $cola2 -Dirs $dirsCola -Config $cfgB -Destino $dirCola)
    Assert-Prueba 'Reanudación' 'Al reanudar, lo ya verificado no se repite y el archivo liberado se recupera' ($cola2[0].Motivo -eq 'verificado al reanudar' -and $cola2[1].Estado -eq 'RECUPERADO_INTEGRO' -and (Get-Hash $cola2[1].Destino) -eq $hEnUso) ('{0} / {1}' -f $cola2[0].Motivo, $cola2[1].Estado)

    # =======================================================================
    Write-Seccion '3. Discos virtuales de prueba'
    $src = New-VhdPrueba -Nombre 'origen' -TamMB 4096 -Particiones @(@{ TamMB = 1600; Fs = 'ntfs'; Etiqueta = 'ORIGEN' }, @{ TamMB = 0; Fs = 'raw'; Etiqueta = '' })
    $S = $src.Letras[0]
    Write-Host ('    ORIGEN: disco #{0}, letras {1}' -f $src.Disco, ($src.Letras -join ', '))
    Assert-Prueba 'Preparación' 'Disco virtual de origen con NTFS y una partición RAW' ($S -and $src.Letras.Count -ge 2) ($src.Letras -join ',')
    $dst = New-VhdPrueba -Nombre 'destino' -TamMB 3072 -Particiones @(@{ TamMB = 0; Fs = 'ntfs'; Etiqueta = 'DESTINO' })
    $D = $dst.Letras[0]
    Write-Host ('    DESTINO: disco #{0}, letra {1}' -f $dst.Disco, $D)

    # Contenido: Windows falso + perfil con casos difíciles
    New-Item -ItemType Directory -Path "$S\Windows\System32\config" -Force | Out-Null
    $u = "$S\Users\Prueba"
    foreach ($carpeta in @("$u\Documents\Sub carpeta", "$u\Documents\node_modules\x", "$u\Desktop", "$u\Pictures", "$u\Downloads", "$S\Espacio")) { New-Item -ItemType Directory -Path $carpeta -Force | Out-Null }
    foreach ($par in @(@('HKLM\SOFTWARE', "$S\Windows\System32\config\SOFTWARE"), @('HKLM\SYSTEM', "$S\Windows\System32\config\SYSTEM"), @('HKCU', "$u\NTUSER.DAT"))) {
        $r = Invoke-Nativo 'reg.exe' @('save', $par[0], $par[1], '/y')
        if ($r.Codigo -ne 0) { throw ('reg save falló: ' + ($r.Salida -join ' ')) }
    }
    foreach ($ensamblado in @('System.IO.Compression', 'System.IO.Compression.FileSystem', 'System.Drawing')) { Add-Type -AssemblyName $ensamblado }
    $zip = [System.IO.Compression.ZipFile]::Open("$u\Documents\carta.docx", 'Create')
    foreach ($e in @(@('[Content_Types].xml', '<Types/>'), @('word/document.xml', ('<w:document>' + ('carta de prueba ñ ' * 400) + '</w:document>')))) {
        $en = $zip.CreateEntry($e[0], [System.IO.Compression.CompressionLevel]::NoCompression); $w = New-Object System.IO.StreamWriter -ArgumentList $en.Open(); $w.Write($e[1]); $w.Dispose()
    }
    $zip.Dispose()
    [System.IO.File]::WriteAllText("$u\Documents\informe ñandú (copia) [1].pdf", ("%PDF-1.4`n" + ('% relleno ' * 600) + "`n%%EOF`n"))
    [System.IO.File]::WriteAllText("$u\Documents\notas.txt", 'Notas de prueba')
    [System.IO.File]::WriteAllText("$u\Documents\Sub carpeta\tabla.csv", "a;b`r`n1;2")
    [System.IO.File]::WriteAllText("$u\Documents\node_modules\x\ignorar.js", '//')
    [System.IO.File]::WriteAllBytes("$u\Documents\danado.bin", (New-Aleatorio 2097152))
    [System.IO.File]::WriteAllBytes("$u\Documents\transitorio.bin", (New-Aleatorio 1048576))
    [System.IO.File]::WriteAllText("$u\Documents\año 2026 – résumé #1 & copia (final)!.txt", 'nombre especial')
    [System.IO.File]::WriteAllText("$u\Documents\日本語 文書.txt", 'unicode')
    $fs = [System.IO.File]::Create("$u\Documents\grande.bin")
    for ($i = 0; $i -lt 75; $i++) { $b = New-Aleatorio 4194304; $fs.Write($b, 0, $b.Length) }
    $fs.Dispose()
    $largo = "$u\Documents\" + ((1..6 | ForEach-Object { ('carpeta_con_nombre_largo_para_superar_los_260_{0}' -f $_) }) -join '\')
    [void][System.IO.Directory]::CreateDirectory('\\?\' + $largo)
    [System.IO.File]::WriteAllText('\\?\' + $largo + '\archivo_en_ruta_larga.txt', 'ruta larga')
    [System.IO.File]::WriteAllText("$u\Documents\bloqueado.txt", 'contenido protegido por permisos')
    [System.IO.File]::WriteAllText("$u\Desktop\nota.txt", 'nota')
    [System.IO.File]::WriteAllText("$u\Desktop\factura.pdf.exe", 'Solo texto: prueba de la heurística de doble extensión.')
    $bmp = New-Object System.Drawing.Bitmap 320, 200
    for ($x = 0; $x -lt 320; $x++) { for ($y = 0; $y -lt 200; $y += 7) { $bmp.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(($x * 3) % 255, ($y * 5) % 255, 90)) } }
    $bmp.Save("$u\Pictures\foto.jpg", [System.Drawing.Imaging.ImageFormat]::Jpeg); $bmp.Dispose()
    $zip = [System.IO.Compression.ZipFile]::Open("$u\Downloads\paquete.zip", 'Create'); $en = $zip.CreateEntry('dato.txt'); $w = New-Object System.IO.StreamWriter -ArgumentList $en.Open(); $w.Write(('x' * 9000)); $w.Dispose(); $zip.Dispose()
    $fs = [System.IO.File]::Create("$S\Espacio\big120.bin"); for ($i = 0; $i -lt 30; $i++) { $b = New-Aleatorio 4194304; $fs.Write($b, 0, $b.Length) }; $fs.Dispose()
    foreach ($k in 1..3) { [System.IO.File]::WriteAllText("$S\Espacio\s$k.txt", ('pequeño ' + $k)) }
    # Hashes de los originales (antes de quitar permisos)
    foreach ($raizH in @(($S + '\Users'), ($S + '\Espacio'))) {
        foreach ($f in [System.IO.Directory]::GetFiles('\\?\' + $raizH, '*', [System.IO.SearchOption]::AllDirectories)) {
            $rel = (Get-RutaCorta $f).Substring(3)
            $originales[$rel] = Get-Hash (Get-RutaCorta $f)
        }
    }
    [void](Invoke-Nativo 'cmd.exe' @('/d', '/c', ('mklink "{0}\Desktop\atajo.txt" "{0}\Documents\notas.txt"' -f $u)))
    [void](Invoke-Nativo 'icacls.exe' @("$u\Documents\bloqueado.txt", '/deny', '*S-1-1-0:(R)'))
    # Archivo BORRADO (para la recuperación por firmas): se crea al final y se elimina
    $bmp = New-Object System.Drawing.Bitmap 300, 180
    for ($x = 0; $x -lt 300; $x += 3) { for ($y = 0; $y -lt 180; $y++) { $bmp.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(200, ($x * 7) % 255, ($y * 3) % 255)) } }
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg); $bmp.Dispose()
    $bytesBorrada = $ms.ToArray(); $ms.Dispose()
    # Escritura directa al disco (WriteThrough + Flush): si se borra mientras sigue en la caché de
    # Windows, sus datos nunca llegan al disco y no hay nada que recuperar (un borrado real sí los deja).
    $fsB = New-Object System.IO.FileStream("$S\borrada.jpg", [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough)
    $fsB.Write($bytesBorrada, 0, $bytesBorrada.Length); $fsB.Flush($true); $fsB.Dispose()
    $hBorrada = Get-Hash "$S\borrada.jpg"
    Start-Sleep -Seconds 2
    Remove-Item -LiteralPath "$S\borrada.jpg" -Force
    $denegado = $false; try { [void][System.IO.File]::ReadAllBytes("$u\Documents\bloqueado.txt") } catch { $denegado = $true }
    Assert-Prueba 'Preparación' 'bloqueado.txt sin permiso de lectura (ni para el administrador)' $denegado
    Write-Host ('    {0} archivos de prueba creados en {1}' -f $originales.Count, $S)

    # =======================================================================
    Write-Seccion '4. Extracción adaptativa (normal, permisos, rutas largas, nombres, errores simulados, interrupción, prioridades, seguridad)'
    $env:TITAN_MODO_PRUEBA = '1'
    $env:TITAN_PRUEBA_FALLOS = 'danado.bin|1048576:8192;transitorio.bin|0:4096:1'
    $env:TITAN_PRUEBA_CORTAR = 'grande.bin|50000000'
    $ra = Invoke-Blackbox -Nombre 'A' -Argumentos @('-RutaRespaldo', ($D + '\'), '-Disco', [string]$src.Disco, '-Estrategia', 'archivos')
    $caso = $ra.Caso
    Assert-Prueba 'Informe' 'Ejecución A termina y deja informe HTML y TXT' ($ra.Codigo -eq 0 -and $caso -and (Test-Path -LiteralPath (Join-Path $caso 'Reporte\reporte.html')) -and (Test-Path -LiteralPath (Join-Path $caso 'Reporte\reporte.txt'))) ('código {0}, caso {1}' -f $ra.Codigo, $caso)
    $filas = Get-Resultados $caso
    foreach ($n in @('carta.docx', 'informe ñandú (copia) [1].pdf', 'notas.txt', 'tabla.csv', 'año 2026 – résumé #1 & copia (final)!.txt', '日本語 文書.txt', 'archivo_en_ruta_larga.txt', 'foto.jpg', 'paquete.zip', 'nota.txt', 'transitorio.bin', 'bloqueado.txt')) {
        $f = Find-Fila $filas $n
        $okH = $false
        if ($f -and $f.Destino) { $rel = (@($originales.Keys | Where-Object { $_.EndsWith('\' + $n) }))[0]; try { $okH = ((Get-Hash $f.Destino) -eq $originales[$rel]) } catch { } }
        Assert-Prueba 'Extracción' ('{0}: RECUPERADO_INTEGRO y SHA-256 igual al original' -f $n) ($f -and $f.Estado -eq 'RECUPERADO_INTEGRO' -and $okH) ($(if ($f) { '{0} | {1}' -f $f.Estado, $f.Motivo } else { 'no está en la cola' }))
    }
    $f = Find-Fila $filas 'bloqueado.txt'
    Assert-Prueba 'Permisos' 'bloqueado.txt se leyó con semántica de copia de seguridad (estrategia alternativa)' ($f -and $f.Estrategia -like 'backup_semantics*') ($f.Estrategia)
    $f = Find-Fila $filas 'transitorio.bin'
    Assert-Prueba 'Reintentos' 'Fallo de lectura transitorio: reintentado y verificado' ($f -and $f.Estado -eq 'RECUPERADO_INTEGRO' -and $f.Estrategia) ($f.Estrategia)
    $f = Find-Fila $filas 'danado.bin'
    $okParcial = $false
    if ($f -and $f.Destino) {
        $copia = [System.IO.File]::ReadAllBytes($f.Destino)
        $ceros = $true; for ($i = 1048576; $i -lt 1056768; $i++) { if ($copia[$i] -ne 0) { $ceros = $false; break } }
        $okParcial = ($f.Estado -eq 'RECUPERADO_PARCIAL' -and [int64]$f.BytesIlegibles -eq 8192 -and $ceros -and $f.Destino -like '*\Parciales\*' -and $copia.Length -eq 2097152)
    }
    Assert-Prueba 'Parcial' 'danado.bin: RECUPERADO_PARCIAL, 8 KiB ilegibles en ceros, guardado en Parciales\' $okParcial ($(if ($f) { '{0} | ilegibles {1} | {2}' -f $f.Estado, $f.BytesIlegibles, $f.Destino }))
    Assert-Prueba 'Parcial' 'danado.bin: su mapa (formato ddrescue) se conserva para reintentar' ($f -and (Test-Path -LiteralPath (Join-Path $caso ('Mapas\' + $f.Id + '.map'))))
    $f = Find-Fila $filas 'grande.bin'
    Assert-Prueba 'Interrupción' 'grande.bin interrumpido: queda PENDIENTE con su mapa' ($f -and $f.Estado -eq 'PENDIENTE' -and (Test-Path -LiteralPath (Join-Path $caso ('Mapas\' + $f.Id + '.map')))) ($(if ($f) { '{0} | {1}' -f $f.Estado, $f.Motivo }))
    $f = Find-Fila $filas 'factura.pdf.exe'
    Assert-Prueba 'Seguridad' 'factura.pdf.exe: OMITIDO_POR_SEGURIDAD y copiado cifrado a Cuarentena' ($f -and $f.Estado -eq 'OMITIDO_POR_SEGURIDAD' -and $f.Destino -like '*.cuar' -and (Test-Path -LiteralPath $f.Destino)) ($(if ($f) { '{0} | {1}' -f $f.Estado, $f.Destino }))
    $f = Find-Fila $filas 'atajo.txt'
    Assert-Prueba 'Seguridad' 'Enlace simbólico: OMITIDO_POR_SEGURIDAD (no se sigue)' ($f -and $f.Estado -eq 'OMITIDO_POR_SEGURIDAD') ($(if ($f) { $f.Estado }))
    Assert-Prueba 'Extracción' 'node_modules excluido por configuración' (-not (Find-Fila $filas 'ignorar.js'))
    # Prioridades: todos los documentos antes que fotos/descargas
    $orden = @([System.IO.File]::ReadAllLines((Join-Path $caso 'Datos\diario.tsv'), [System.Text.Encoding]::UTF8) | Select-Object -Skip 1 | Where-Object { $_.Split("`t")[2] -like 'RECUPERADO*' } | ForEach-Object { $_.Split("`t")[12] })
    $iFoto = [Array]::IndexOf($orden, ($orden | Where-Object { $_ -like '*foto.jpg' } | Select-Object -First 1))
    $iCarta = [Array]::IndexOf($orden, ($orden | Where-Object { $_ -like '*carta.docx' } | Select-Object -First 1))
    $iZip = [Array]::IndexOf($orden, ($orden | Where-Object { $_ -like '*paquete.zip' } | Select-Object -First 1))
    Assert-Prueba 'Prioridades' 'Documentos antes que fotos, y fotos antes que Descargas' ($iCarta -ge 0 -and $iCarta -lt $iFoto -and $iFoto -lt $iZip) ('carta {0}, foto {1}, zip {2}' -f $iCarta, $iFoto, $iZip)
    $tj = $null
    if (Test-Path -LiteralPath (Join-Path $caso 'trabajo.json')) { $tj = Get-Content -LiteralPath (Join-Path $caso 'trabajo.json') -Raw -Encoding UTF8 | ConvertFrom-Json }
    if (-not $tj) { $tj = [pscustomobject]@{ Volumenes = @() } }
    Assert-Prueba 'Volúmenes' 'La partición RAW se detecta como VOLUMEN_NO_RECONOCIDO' (@($tj.Volumenes | Where-Object { $_.Estado -eq 'VOLUMEN_NO_RECONOCIDO' }).Count -ge 1) (($tj.Volumenes | ForEach-Object { $_.Letra + '=' + $_.Estado }) -join ', ')
    Assert-Prueba 'Volúmenes' 'El volumen NTFS se detecta como LEGIBLE' (@($tj.Volumenes | Where-Object { $_.Estado -eq 'LEGIBLE' }).Count -ge 1)
    $escribio = $true
    try { [System.IO.File]::WriteAllText("$S\escritura_prohibida.txt", 'x') } catch { $escribio = $false }
    Assert-Prueba 'Solo lectura' 'Escribir en el disco de origen está bloqueado' (-not $escribio)
    Assert-Prueba 'Solo lectura' 'El origen sigue intacto (notas.txt igual al original)' ((Get-Hash "$u\Documents\notas.txt") -eq $originales['Users\Prueba\Documents\notas.txt'])
    $rep = [System.IO.File]::ReadAllText((Join-Path $caso 'Reporte\reporte.txt'))
    foreach ($sec in @('EQUIPO Y DISPOSITIVO', 'HECHOS COMPROBADOS', 'RESULTADOS PARCIALES', 'CONCLUSIONES INCIERTAS', 'ERRORES POR CATEGORÍA', 'ESTRATEGIAS APLICADAS', 'HERRAMIENTAS', 'VERIFICACIÓN', 'RECOMENDACIONES', 'RECUPERADO_PARCIAL', 'Bytes recuperados')) {
        Assert-Prueba 'Informe' ('El informe incluye "{0}"' -f $sec) ($rep.Contains($sec))
    }

    # =======================================================================
    Write-Seccion '5. Reanudación (y detección de copias alteradas)'
    $fNotas = Find-Fila $filas 'notas.txt'
    if (-not ($fNotas -and $fNotas.Destino)) { throw 'La ejecución A no dejó notas.txt recuperado: no se puede probar la reanudación.' }
    [System.IO.File]::AppendAllText($fNotas.Destino, ' ALTERADO')
    [Environment]::SetEnvironmentVariable('TITAN_PRUEBA_CORTAR', $null, 'Process')
    $rb = Invoke-Blackbox -Nombre 'B' -Argumentos @('-RutaRespaldo', ($D + '\'), '-Disco', [string]$src.Disco, '-Estrategia', 'archivos', '-Reanudar', $caso)
    $filas2 = Get-Resultados $caso
    $f = Find-Fila $filas2 'grande.bin'
    $hg = ''; if ($f -and $f.Destino) { $hg = Get-Hash $f.Destino }
    Assert-Prueba 'Reanudación' 'grande.bin continúa desde su mapa y queda íntegro' ($rb.Codigo -eq 0 -and $f.Estado -eq 'RECUPERADO_INTEGRO' -and $hg -eq $originales['Users\Prueba\Documents\grande.bin']) ($(if ($f) { '{0} | {1}' -f $f.Estado, $f.Motivo }))
    $f = Find-Fila $filas2 'notas.txt'
    Assert-Prueba 'Verificación' 'La copia alterada se detecta por SHA-256 y se vuelve a copiar' ($f.Estado -eq 'RECUPERADO_INTEGRO' -and (Get-Hash $f.Destino) -eq $originales['Users\Prueba\Documents\notas.txt'] -and (Get-EntradasDiario $caso $f.Id).Count -eq 2) ('{0} entradas en el diario' -f (Get-EntradasDiario $caso $f.Id).Count)
    $f = Find-Fila $filas2 'carta.docx'
    Assert-Prueba 'Reanudación' 'Lo ya verificado no se vuelve a copiar (carta.docx: 1 sola copia)' ($f.Estado -eq 'RECUPERADO_INTEGRO' -and (Get-EntradasDiario $caso $f.Id).Count -eq 1 -and $f.Motivo -eq 'verificado al reanudar') ('{0} | {1}' -f (Get-EntradasDiario $caso $f.Id).Count, $f.Motivo)
    $f = Find-Fila $filas2 'danado.bin'
    Assert-Prueba 'Parcial' 'El parcial se reintenta al reanudar y sigue PARCIAL (la zona es ilegible de verdad)' ($f.Estado -eq 'RECUPERADO_PARCIAL' -and (Get-EntradasDiario $caso $f.Id).Count -eq 2) ('{0}, {1} entradas' -f $f.Estado, (Get-EntradasDiario $caso $f.Id).Count)

    # =======================================================================
    Write-Seccion '6. Identificación incorrecta del dispositivo'
    $casosAntes = @(Get-ChildItem -LiteralPath ($D + '\Casos') -Directory -ErrorAction SilentlyContinue).Count
    $rc = Invoke-Blackbox -Nombre 'C' -Argumentos @('-RutaRespaldo', ($D + '\'), '-Disco', [string]$dst.Disco, '-Estrategia', 'archivos')
    $casosDespues = @(Get-ChildItem -LiteralPath ($D + '\Casos') -Directory -ErrorAction SilentlyContinue).Count
    Assert-Prueba 'Identificación' 'Elegir como origen el disco del destino: se detiene ("Protección")' ($rc.Codigo -ne 0 -and $rc.Texto -match 'Protecci') ('código {0}' -f $rc.Codigo)
    Assert-Prueba 'Solo lectura' 'Y no escribe nada en ese disco (ni carpeta de trabajo ni registros)' ($casosDespues -eq $casosAntes) ('casos antes {0}, después {1}' -f $casosAntes, $casosDespues)
    $rc2 = Invoke-Blackbox -Nombre 'C2' -Argumentos @('-RutaRespaldo', ($S + '\Espacio\'), '-Disco', [string]$src.Disco, '-Estrategia', 'archivos')
    Assert-Prueba 'Identificación' 'Destino dentro del disco de origen (BLACKBOX completo): se detiene' ($rc2.Codigo -ne 0 -and $rc2.Texto -match 'Protecci') ('código {0}' -f $rc2.Codigo)
    Assert-Prueba 'Solo lectura' 'Y no crea nada en el disco de origen' (-not (Test-Path -LiteralPath ($S + '\Espacio\Casos'))) ''
    $fallo = $null
    try { [void](Test-SeguridadOperacion -DiscoOrigen $src.Disco -DiscoUsb $dst.Disco -Destino ($S + '\')) } catch { $fallo = $_.Exception.Message }
    Assert-Prueba 'Identificación' 'Destino dentro del disco de origen: rechazado' ($fallo -like '*destino*') $fallo
    $fallo = $null
    try { [void](Test-SeguridadOperacion -DiscoOrigen $dst.Disco -DiscoUsb $dst.Disco -Destino ($D + '\')) } catch { $fallo = $_.Exception.Message }
    Assert-Prueba 'Identificación' 'Origen = USB de trabajo: rechazado' ($fallo -like '*USB*') $fallo
    $r = Invoke-Motor -Argumentos @('copiar', '--origen', "$u\Documents\notas.txt", '--destino', ('\\.\PhysicalDrive' + $src.Disco), '--mapa', "$tmp\x.map")
    Assert-Prueba 'Solo lectura' 'El motor se niega a escribir en un dispositivo' ($r.estado -eq 'RECHAZADO') $r.estado
    $r = Invoke-Motor -Argumentos @('reconstruir-mbr', '--imagen', ('\\.\PhysicalDrive' + $src.Disco), '--particiones', '1048576:1000:07')
    Assert-Prueba 'Solo lectura' 'Reconstruir particiones sobre un disco real: rechazado (solo sobre imágenes)' ($r.estado -eq 'RECHAZADO') $r.estado

    # =======================================================================
    Write-Seccion '7. Destino sin espacio'
    $chico = New-VhdPrueba -Nombre 'chico' -TamMB 100 -Particiones @(@{ TamMB = 0; Fs = 'ntfs'; Etiqueta = 'CHICO' })
    $cfgTxt = Get-Content -LiteralPath (Join-Path $scripts 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $cfgTxt.Blackbox.MargenLibreMB = 1
    $rutaCfg = Join-Path $tmp 'config_prueba.json'
    [System.IO.File]::WriteAllText($rutaCfg, ($cfgTxt | ConvertTo-Json -Depth 6), $script:Utf8SinBom)
    $re = Invoke-Blackbox -Nombre 'E' -Argumentos @('-RutaRespaldo', ($chico.Letras[0] + '\'), '-Disco', [string]$src.Disco, '-Estrategia', 'archivos', '-CarpetasPrueba', ($S + '\Espacio'), '-RutaConfig', $rutaCfg)
    $fe = Get-Resultados $re.Caso
    $f = Find-Fila $fe 'big120.bin'
    Assert-Prueba 'Sin espacio' 'Archivo que no cabe: PENDIENTE (DESTINO_SIN_ESPACIO) sin llenar el destino' ($f -and $f.Estado -eq 'PENDIENTE' -and $f.Motivo -like '*DESTINO_SIN_ESPACIO*') ($(if ($f) { '{0} | {1}' -f $f.Estado, $f.Motivo }))
    $peq = @($fe | Where-Object { $_.Ruta -like '*\s?.txt' -and $_.Estado -eq 'RECUPERADO_INTEGRO' })
    Assert-Prueba 'Sin espacio' 'Los archivos que sí caben se recuperan igualmente' ($peq.Count -eq 3) ('{0} de 3' -f $peq.Count)
    Assert-Prueba 'Informe' 'Con archivos pendientes por falta de espacio, igualmente se genera el informe' ($re.Caso -and (Test-Path -LiteralPath (Join-Path $re.Caso 'Reporte\reporte.html'))) ($re.Caso)

    # =======================================================================
    Write-Seccion '8. Imagen sector a sector y extracción desde la imagen'
    $src2 = New-VhdPrueba -Nombre 'origen2' -TamMB 256 -Particiones @(@{ TamMB = 0; Fs = 'ntfs'; Etiqueta = 'IMG_ORIGEN' })
    $S2 = $src2.Letras[0]
    New-Item -ItemType Directory -Path "$S2\Carpeta" -Force | Out-Null
    [System.IO.File]::WriteAllBytes("$S2\uno.bin", (New-Aleatorio 300000))
    Copy-Item -LiteralPath "$u\Pictures\foto.jpg" -Destination "$S2\Carpeta\dos.jpg"
    [System.IO.File]::WriteAllText("$S2\Carpeta\tres ñ.txt", 'tres')
    $h2 = @{ 'uno.bin' = (Get-Hash "$S2\uno.bin"); 'dos.jpg' = (Get-Hash "$S2\Carpeta\dos.jpg"); 'tres ñ.txt' = (Get-Hash "$S2\Carpeta\tres ñ.txt") }
    $rf = Invoke-Blackbox -Nombre 'F' -Argumentos @('-RutaRespaldo', ($D + '\'), '-Disco', [string]$src2.Disco, '-Estrategia', 'imagen')
    $ff = Get-Resultados $rf.Caso
    Assert-Prueba 'Imagen' 'Imagen completa creada con su mapa y convertida a VHD' ($rf.Codigo -eq 0 -and @(Get-ChildItem -LiteralPath (Join-Path $rf.Caso 'Imagenes') -Filter '*.vhd').Count -eq 1 -and @(Get-ChildItem -LiteralPath (Join-Path $rf.Caso 'Imagenes') -Filter '*.map').Count -eq 1) ('código {0}' -f $rf.Codigo)
    foreach ($n in $h2.Keys) {
        $f = Find-Fila $ff $n
        Assert-Prueba 'Imagen' ('{0} extraído desde la imagen montada en solo lectura, SHA-256 igual al original' -f $n) ($f -and $f.Estado -eq 'RECUPERADO_INTEGRO' -and (Get-Hash $f.Destino) -eq $h2[$n]) ($(if ($f) { $f.Estado } else { 'no extraído' }))
    }

    # =======================================================================
    Write-Seccion '9. Particiones perdidas: búsqueda y reconstrucción sobre una COPIA de imagen'
    $img2 = Join-Path $tmp 'origen2.img'
    $ri = Invoke-Motor -Argumentos @('imagen', '--origen', ('\\.\PhysicalDrive' + $src2.Disco), '--destino', $img2, '--mapa', ($img2 + '.map'))
    Assert-Prueba 'Particiones' 'Imagen directa del disco virtual (lectura de dispositivo con el motor)' ($ri.estado -like 'RECUPERADO*' -and $ri.bytesMalos -eq 0) $ri.estado
    $fsImg = [System.IO.File]::Open($img2, 'Open', 'ReadWrite'); $fsImg.Write((New-Object byte[] 512), 0, 512); $fsImg.Dispose()
    $rp = Invoke-Motor -Argumentos @('particiones', '--origen', $img2)
    Assert-Prueba 'Particiones' 'Con la tabla borrada, la partición NTFS aparece como perdida' (@($rp.halladas | Where-Object { $_.fs -eq 'NTFS' -and -not $_.enTabla }).Count -eq 1) ($rp | ConvertTo-Json -Compress -Depth 4)
    $rg = Invoke-Blackbox -Nombre 'G' -Argumentos @('-RutaRespaldo', ($D + '\'), '-Disco', [string]$src2.Disco, '-Estrategia', 'particiones', '-ImagenParticion', $img2)
    $fg = Get-Resultados $rg.Caso
    Assert-Prueba 'Particiones' 'MBR reconstruido solo en la copia (sector 0 original guardado)' (Test-Path -LiteralPath ($img2 + '.sector0.bak'))
    foreach ($n in $h2.Keys) {
        $f = Find-Fila $fg $n
        Assert-Prueba 'Particiones' ('{0} recuperado de la partición perdida, SHA-256 igual al original' -f $n) ($f -and $f.Estado -eq 'RECUPERADO_INTEGRO' -and (Get-Hash $f.Destino) -eq $h2[$n]) ($(if ($f) { $f.Estado } else { 'no extraído' }))
    }

    # =======================================================================
    Write-Seccion '10. Recuperación por firmas (incluido un archivo BORRADO)'
    $rh = Invoke-Blackbox -Nombre 'H' -Argumentos @('-RutaRespaldo', ($D + '\'), '-Disco', [string]$src.Disco, '-Estrategia', 'firmas', '-OrigenFirmas', ('\\.\' + $S))
    $csvF = Join-Path $rh.Caso 'Datos\firmas.csv'
    $firmas = @(); if (Test-Path -LiteralPath $csvF) { $firmas = @(Import-Csv -LiteralPath $csvF -Delimiter ';' -Encoding UTF8) }
    $hashesF = @($firmas | ForEach-Object { $_.sha256 })
    Assert-Prueba 'Firmas' 'foto.jpg recuperada por firma, idéntica' ($hashesF -contains $originales['Users\Prueba\Pictures\foto.jpg']) ('{0} archivos por firma' -f $firmas.Count)
    Assert-Prueba 'Firmas' 'borrada.jpg (ARCHIVO ELIMINADO) recuperada por firma, idéntica' ($hashesF -contains $hBorrada)
    Assert-Prueba 'Firmas' 'carta.docx recuperada por firma, idéntica' ($hashesF -contains $originales['Users\Prueba\Documents\carta.docx'])
    $repH = [System.IO.File]::ReadAllText((Join-Path $rh.Caso 'Reporte\reporte.txt'))
    Assert-Prueba 'Firmas' 'El informe advierte que por firma se pierden nombres y puede haber fragmentación' ($repH -match 'sin nombres' -and $repH -match 'fragmentad')

    # =======================================================================
    Write-Seccion '11. Regresión: simulacro del rescate seguro (PROBAR-TITAN)'
    [Environment]::SetEnvironmentVariable('TITAN_PRUEBA_FALLOS', $null, 'Process')
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $rt = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $aqui 'Probar-TITAN.ps1') 2>&1 | ForEach-Object { [string]$_ }
    $ErrorActionPreference = $eap
    Assert-Prueba 'Regresión' 'El rescate seguro sigue funcionando (SIMULACRO COMPLETO SIN FALLOS)' (($rt -join "`n") -match 'SIMULACRO COMPLETO SIN FALLOS') (($rt | Select-Object -Last 3) -join ' | ')
} catch {
    Assert-Prueba 'General' 'La batería de pruebas terminó sin excepciones' $false ('{0} (línea {1})' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber)
} finally {
    foreach ($ve in @('TITAN_MODO_PRUEBA', 'TITAN_PRUEBA_FALLOS', 'TITAN_PRUEBA_CORTAR')) { [Environment]::SetEnvironmentVariable($ve, $null, 'Process') }
    Write-Seccion 'Limpieza de los discos virtuales'
    try {
        # Antes de borrar: se guardan registros y la salida de diskpart para poder diagnosticar
        $regs = Join-Path $repo ('registros_prueba\' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
        New-Item -ItemType Directory -Path $regs -Force | Out-Null
        Get-ChildItem -LiteralPath $tmp -Filter 'blackbox_*.txt' -File -ErrorAction SilentlyContinue | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $regs -Force }
        foreach ($dp in $discosPrueba) {
            $txt = Invoke-Diskpart @("select disk $($dp.Disco)", 'detail disk', 'uniqueid disk')
            [System.IO.File]::WriteAllLines((Join-Path $regs ('diskpart_disco_{0}.txt' -f $dp.Disco)), [string[]]$txt, $script:Utf8ConBom)
            foreach ($v in (Get-DetalleDiscoDp -Numero $dp.Disco).Volumenes) {
                if (-not $v.Letra) { continue }
                $casos = $v.Letra + ':\Casos'
                if (Test-Path -LiteralPath $casos) {
                    Get-ChildItem -LiteralPath $casos -Directory | ForEach-Object {
                        $d2 = Join-Path $regs $_.Name
                        New-Item -ItemType Directory -Path $d2 -Force | Out-Null
                        Get-ChildItem -LiteralPath (Join-Path $_.FullName 'Registros') -File -ErrorAction SilentlyContinue | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $d2 -Force }
                    }
                }
            }
        }
        Write-Host ('    Registros guardados en {0}' -f $regs)
    } catch { Write-Host ('    No se pudieron guardar los registros: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }
    foreach ($dp in $discosPrueba) {
        [void](Invoke-Diskpart @("select disk $($dp.Disco)", 'attributes disk clear readonly noerr'))
        [void](Invoke-Diskpart @(('select vdisk file="{0}"' -f $dp.Ruta), 'detach vdisk noerr'))
    }
    Start-Sleep -Seconds 2
    try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction Stop; Write-Host '    Carpeta temporal borrada.' } catch { Write-Host ('    No se pudo borrar {0}: {1}' -f $tmp, $_.Exception.Message) -ForegroundColor Yellow }
}

Write-Seccion 'RESUMEN'
$porCaso = $script:Resultados | Group-Object Caso
foreach ($g in $porCaso) {
    $ok = @($g.Group | Where-Object { $_.Ok }).Count
    Write-Host ('  {0,-16} {1,3} / {2,-3}' -f $g.Name, $ok, $g.Count) -ForegroundColor $(if ($ok -eq $g.Count) { 'Green' } else { 'Red' })
}
$fallos = @($script:Resultados | Where-Object { -not $_.Ok }).Count
Write-Host ''
if ($fallos -eq 0) { Write-Host ('BLACKBOX: {0} PRUEBAS, TODAS CORRECTAS' -f $script:Resultados.Count) -ForegroundColor Green }
else { Write-Host ('BLACKBOX: {0} PRUEBAS, {1} FALLIDAS' -f $script:Resultados.Count, $fallos) -ForegroundColor Red }
try { Stop-Transcript | Out-Null } catch { }
