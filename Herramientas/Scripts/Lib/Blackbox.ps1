<#
    Blackbox.ps1 - Biblioteca de TITAN BLACKBOX (recuperación avanzada).

    Reutiliza lo que ya funciona en TITAN (diskpart, solo lectura, BitLocker,
    perfiles y carpetas, cuarentena cifrada, SHA-256, ClamAV, registro) y añade:
      - el motor TitanRescate.exe (copia por bloques con mapa reanudable,
        imágenes, VHD, particiones, firmas, salud NVMe);
      - cola de recuperación priorizada y reanudable (diario append-only);
      - clasificación de cada fallo y estrategia por categoría;
      - estados finales por archivo e informe ampliado.

    Compatible con Windows PowerShell 5.1 (WinPE-PowerShell). Sin WMI.
#>

$script:EstadosFinales = @('RECUPERADO_INTEGRO', 'RECUPERADO_PARCIAL', 'RECUPERADO_SIN_VERIFICACION_COMPLETA', 'ERROR_RECUPERACION', 'OMITIDO_POR_SEGURIDAD')
$script:RutaMotor = $null
$script:VersionMotor = ''
$script:ArchivoDiario = $null

# Categorías del pliego y la estrategia que activa cada una
$script:EstrategiaPorCategoria = [ordered]@{
    'ARCHIVO_INACCESIBLE'            = 'Reencolar al final (puede estar en uso); máximo de intentos limitado'
    'PROBLEMA_PERMISOS'              = 'Lectura con semántica de copia de seguridad (SeBackupPrivilege), solo lectura'
    'RUTA_DEMASIADO_LARGA'           = 'Rutas con prefijo \\?\ (hasta 32.767 caracteres)'
    'ERROR_LECTURA'                  = 'Copia por bloques: salta la zona, raspa sector a sector y reintenta lo malo'
    'VOLUMEN_BLOQUEADO'              = 'Desbloqueo con la clave de recuperación de BitLocker (nunca se elude el cifrado)'
    'VOLUMEN_NO_RECONOCIDO'          = 'Búsqueda de particiones perdidas y recuperación por firmas (sin escribir en el disco)'
    'ARCHIVO_PARCIALMENTE_LEGIBLE'   = 'Se conserva la parte legible con su mapa; se puede reanudar más tarde'
    'DISCO_POSIBLE_FALLO_FISICO'     = 'Modo de fallo: primera pasada rápida para todo, prioridad a lo importante, sin insistir'
    'DESTINO_SIN_ESPACIO'            = 'Se omite ese archivo, se sigue con los que caben y queda PENDIENTE'
    'HERRAMIENTA_INCOMPATIBLE'       = 'Se usa la alternativa integrada y se registra la limitación'
    'ERROR_INTEGRIDAD'               = 'Se repite la copia una vez; si vuelve a fallar, ERROR'
    'DISPOSITIVO_DESCONECTADO'       = 'Se detiene la cola guardando el estado (reanudable)'
}

# ---------------------------------------------------------------------------
# Motor TitanRescate.exe
# ---------------------------------------------------------------------------
function Initialize-MotorRescate {
    <#
      Localiza el motor y lo verifica contra el ancla; lo copia a la RAM (X:)
      y lo vuelve a comprobar antes de usarlo. Fuera de WinPE (pruebas) se
      admite una ruta explícita.
    #>
    param([string]$RutaHerramientas, [string]$RutaExplicita, [switch]$SinAncla)
    if ($RutaExplicita) {
        if (-not (Test-Path -LiteralPath $RutaExplicita)) { throw "No existe el motor $RutaExplicita" }
        $script:RutaMotor = $RutaExplicita
    } else {
        $orig = Join-Path $RutaHerramientas 'Blackbox\TitanRescate.exe'
        if (-not (Test-Path -LiteralPath $orig)) { throw 'Falta Blackbox\TitanRescate.exe en el USB (actualice TITAN con ACTUALIZAR-TITAN.bat).' }
        if (-not $SinAncla) {
            $pr = Test-ArchivosContraAncla -RutaHerramientas $RutaHerramientas -Prefijo 'Blackbox\'
            if ($pr.Count -gt 0) { throw ('El motor no coincide con el ancla: ' + ($pr -join '; ')) }
        }
        $ram = Join-Path $env:SystemDrive 'Trabajo\Blackbox'
        New-Item -ItemType Directory -Path $ram -Force | Out-Null
        $copia = Join-Path $ram 'TitanRescate.exe'
        Copy-Item -LiteralPath $orig -Destination $copia -Force
        if (-not $SinAncla) {
            $ancla = Get-HashesAncla
            $esperado = $ancla['blackbox\titanrescate.exe']
            if (-not $esperado -or (Get-Sha256Archivo -Ruta $copia).Hash -ne $esperado) { throw 'La copia del motor en RAM no coincide con el ancla.' }
        }
        $script:RutaMotor = $copia
    }
    $v = Invoke-Motor -Argumentos @('version')
    if ($v.estado -ne 'OK') { throw ('El motor no arranca en este entorno: ' + $v.mensaje) }
    if (-not $v.x64) { throw 'El motor no corre en 64 bits.' }
    $script:VersionMotor = 'TitanRescate {0} (CLR {1})' -f $v.version, $v.clr
    return $script:VersionMotor
}

function Invoke-Motor {
    # Ejecuta el motor; muestra su progreso y devuelve el objeto de resultado.
    param([string[]]$Argumentos, [switch]$Progreso)
    $resultado = $null
    $otras = [System.Collections.Generic.List[string]]::new()
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $ultimo = [DateTime]::MinValue
    try {
        & $script:RutaMotor @Argumentos 2>&1 | ForEach-Object {
            $s = [string]$_
            if ($s.StartsWith('TITAN_RESULTADO ')) { $resultado = $s.Substring(16) }
            elseif ($s.StartsWith('TITAN_PROGRESO ')) {
                if ($Progreso -and ([DateTime]::Now - $ultimo).TotalSeconds -ge 5) {
                    $ultimo = [DateTime]::Now
                    Write-Host ('    ' + (ConvertTo-TextoProgreso $s.Substring(15))) -ForegroundColor DarkGray
                }
            }
            elseif ($s.Trim()) { $otras.Add($s) }
        }
    } catch {
        $otras.Add($_.Exception.Message)
    } finally { $ErrorActionPreference = $eap }
    $codigo = $LASTEXITCODE
    $obj = $null
    if ($resultado) { try { $obj = $resultado | ConvertFrom-Json } catch { $obj = $null } }
    if ($null -eq $obj) {
        $obj = [pscustomobject]@{ estado = 'ERROR'; categoria = 'HERRAMIENTA_INCOMPATIBLE'; codigoWin32 = 0
            mensaje = ('El motor no devolvió resultado (código {0}): {1}' -f $codigo, ($otras.ToArray() -join ' | ')) }
    }
    $obj | Add-Member -NotePropertyName CodigoSalida -NotePropertyValue $codigo -Force
    if ($Argumentos.Count -gt 0 -and $Argumentos[0] -notin @('copiar', 'sha256')) {
        # Registro de diagnóstico de cada operación del motor (no de cada archivo copiado)
        Write-Log ('Motor {0}: {1}' -f $Argumentos[0], (ConvertTo-Json -InputObject $obj -Compress -Depth 4)) -SoloArchivo
    }
    return $obj
}

function ConvertTo-TextoProgreso {
    param([string]$T)
    $p = $T -split ' '
    if ($p.Count -ge 3 -and $p[1] -match '^\d+$' -and $p[2] -match '^\d+$' -and [int64]$p[2] -gt 0) {
        $pct = [Math]::Round(100.0 * [int64]$p[1] / [int64]$p[2], 1)
        $resto = ''
        if ($p.Count -gt 3) { $resto = ' ' + (($p[3..($p.Count - 1)]) -join ' ') }
        return ('{0}: {1}% ({2} de {3}){4}' -f $p[0], $pct, (Format-Bytes ([double]$p[1])), (Format-Bytes ([double]$p[2])), $resto)
    }
    return $T
}

# ---------------------------------------------------------------------------
# Seguridad de la operación (pliego, fase 6)
# ---------------------------------------------------------------------------
function Get-SerieVolumen {
    # Número de serie del volumen con "vol" (sin WMI). Devuelve 'XXXX-XXXX' o ''.
    param([string]$Letra)
    $r = Invoke-Nativo 'cmd.exe' @('/d', '/c', ('vol {0}' -f $Letra.Substring(0, 2)))
    $m = [regex]::Match(($r.Salida -join ' '), '\b([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})\b')
    if ($m.Success) { return $m.Groups[1].Value.ToUpperInvariant() }
    return ''
}

function Test-SeguridadOperacion {
    <#
      Comprobaciones obligatorias antes de tocar nada. Devuelve un objeto con la
      lista de comprobaciones; lanza una excepción si alguna falla.
        1. Disco de origen identificado (número, modelo, tamaño, volúmenes)
        2. USB de TITAN identificada por su firma de disco
        3. El origen no es la USB de TITAN
        4. El destino no está en el disco de origen
        5. Estado de solo lectura del origen (si se pide)
        6. Espacio disponible en el destino
    #>
    param([int]$DiscoOrigen, [int]$DiscoUsb, [string]$Destino, [int64]$EspacioMinimo = 0, [switch]$ExigirSoloLectura, [string]$FirmaUsbEsperada)
    $c = [System.Collections.Generic.List[object]]::new()
    $fallo = $null
    $det = Get-DetalleDiscoConTamanoDp -Numero $DiscoOrigen
    $ok1 = ($det.Id -and $det.FriendlyName)
    $c.Add([pscustomobject]@{ Comprobacion = 'Disco de origen identificado'; Ok = [bool]$ok1; Detalle = ('#{0} {1} | id {2} | {3} | {4} volúmenes' -f $DiscoOrigen, $det.FriendlyName, $det.Id, (Format-Bytes ([double]$det.Size)), @($det.Volumenes).Count) })
    if (-not $ok1 -and -not $fallo) {
        $fallo = ('No se pudo identificar el disco de origen #{0} (modelo: "{1}", id: "{2}").' -f $DiscoOrigen, $det.FriendlyName, $det.Id)
        Write-DiagnosticoDp -Numero $DiscoOrigen -Motivo 'disco de origen sin identificar'
    }
    $usb = Get-DetalleDiscoDp -Numero $DiscoUsb
    $ok2 = $true
    if ($FirmaUsbEsperada) { $ok2 = ($usb.Id -eq $FirmaUsbEsperada) }
    $c.Add([pscustomobject]@{ Comprobacion = 'USB de TITAN identificada por su firma'; Ok = $ok2; Detalle = ('#{0} firma {1} (esperada {2})' -f $DiscoUsb, $usb.Id, $FirmaUsbEsperada) })
    if (-not $ok2 -and -not $fallo) { $fallo = 'La USB de trabajo no es la sellada en el ancla.' }
    $ok3 = ($DiscoOrigen -ne $DiscoUsb -and $det.Id -ne $usb.Id)
    $c.Add([pscustomobject]@{ Comprobacion = 'El origen no es la USB de TITAN'; Ok = $ok3; Detalle = ('origen #{0} / USB #{1}' -f $DiscoOrigen, $DiscoUsb) })
    if (-not $ok3 -and -not $fallo) { $fallo = 'El disco de origen es la propia USB de TITAN.' }
    $discoDestino = Get-NumeroDiscoDeVolumenDp -Letra $Destino
    $ok4 = ($discoDestino -ge 0 -and $discoDestino -ne $DiscoOrigen)
    $c.Add([pscustomobject]@{ Comprobacion = 'El destino no está en el disco de origen'; Ok = $ok4; Detalle = ('destino {0} en el disco #{1}' -f $Destino, $discoDestino) })
    if (-not $ok4 -and -not $fallo) { $fallo = ('El destino {0} está en el disco de origen (o no se pudo identificar su disco).' -f $Destino) }
    if ($ExigirSoloLectura) {
        $ok5 = Test-DiscoSoloLectura -Numero $DiscoOrigen
        $c.Add([pscustomobject]@{ Comprobacion = 'Origen en solo lectura'; Ok = [bool]$ok5; Detalle = '' })
        if (-not $ok5 -and -not $fallo) { $fallo = 'El disco de origen no está en solo lectura.' }
    }
    $libre = Get-EspacioLibre $Destino
    $ok6 = ($libre -ge $EspacioMinimo)
    $c.Add([pscustomobject]@{ Comprobacion = 'Espacio en el destino'; Ok = $ok6; Detalle = ('libre {0}, mínimo {1}' -f (Format-Bytes ([double]$libre)), (Format-Bytes ([double]$EspacioMinimo))) })
    if (-not $ok6 -and -not $fallo) { $fallo = 'No hay espacio suficiente en el destino.' }
    foreach ($x in $c) {
        $nivel = 'OK'; if (-not $x.Ok) { $nivel = 'ERROR' }
        Write-Log ('Seguridad: {0}: {1} ({2})' -f $x.Comprobacion, $(if ($x.Ok) { 'correcto' } else { 'FALLA' }), $x.Detalle) -Nivel $nivel -SoloArchivo
    }
    $res = [pscustomobject]@{ Ok = (-not $fallo); Motivo = $fallo; Comprobaciones = $c.ToArray(); Origen = $det; Usb = $usb; DiscoDestino = $discoDestino }
    if ($fallo) { throw ('Operación detenida por seguridad: ' + $fallo) }
    return $res
}

# ---------------------------------------------------------------------------
# Diagnóstico de volúmenes
# ---------------------------------------------------------------------------
function Get-DiagnosticoVolumenes {
    <#
      Clasifica cada volumen del disco leyendo su sector de arranque con el motor
      (no depende de manage-bde ni de WMI):
        LEGIBLE | VOLUMEN_BLOQUEADO (BitLocker) | VOLUMEN_NO_RECONOCIDO | OCULTO_O_SISTEMA | SIN_LETRA
    #>
    param([int]$Numero)
    $res = [System.Collections.Generic.List[object]]::new()
    foreach ($v in (Get-DetalleDiscoDp -Numero $Numero).Volumenes) {
        $letra = ''; if ($v.Letra) { $letra = $v.Letra + ':' }
        $estado = 'SIN_LETRA'; $bitlocker = 'No'; $serie = ''; $tipo = ''
        if ($letra) {
            $mv = Invoke-Motor -Argumentos @('volumen', '--origen', ('\\.\{0}' -f $letra))
            $tipo = [string]$mv.tipo
            $legible = $false
            try { [void][System.IO.Directory]::GetFileSystemEntries($letra + '\'); $legible = $true } catch { }
            if ($mv.bitlocker) { $bitlocker = 'Sí (' + $(if ($legible) { 'desbloqueado' } else { 'BLOQUEADO' }) + ')' }
            if ($legible) {
                $estado = 'LEGIBLE'; $serie = Get-SerieVolumen -Letra $letra
                if (-not $mv.bitlocker -and (Get-EstadoBitLocker -Letra $letra) -eq 'Desbloqueado') { $bitlocker = 'Sí (desbloqueado)' }
            }
            elseif ($mv.bitlocker) { $estado = 'VOLUMEN_BLOQUEADO' }
            else { $estado = 'VOLUMEN_NO_RECONOCIDO' }
        } elseif ($v.Info -match '(?i)(hidden|oculto|system|sistema)') { $estado = 'OCULTO_O_SISTEMA' }
        $res.Add([pscustomobject]@{ Num = $v.Num; Letra = $letra; Fs = $v.Fs; Tamano = $v.Tamano; Info = $v.Info; Estado = $estado; BitLocker = $bitlocker; Serie = $serie; Firma = $tipo })
    }
    return $res.ToArray()
}

# ---------------------------------------------------------------------------
# Trabajo, diario y reanudación
# ---------------------------------------------------------------------------
function New-TrabajoBlackbox {
    param([string]$Caso, $Identidad)
    $dirs = [ordered]@{
        Caso = $Caso; Respaldo = "$Caso\Respaldo"; Parciales = "$Caso\Parciales"; Mapas = "$Caso\Mapas"; EnCurso = "$Caso\EnCurso"
        Cuarentena = "$Caso\Cuarentena"; Registros = "$Caso\Registros"; Datos = "$Caso\Datos"; Reporte = "$Caso\Reporte"
        Imagenes = "$Caso\Imagenes"; Firmas = "$Caso\RecuperadosPorFirma"; Trabajo = "$Caso\Trabajo"; Tmp = "$Caso\Trabajo\tmp"
    }
    foreach ($d in $dirs.Values) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $script:ArchivoDiario = Join-Path $dirs.Datos 'diario.tsv'
    if (-not (Test-Path -LiteralPath $script:ArchivoDiario)) {
        [System.IO.File]::WriteAllText($script:ArchivoDiario, "Fecha`tId`tEstado`tCategoria`tIntento`tEstrategia`tTamano`tBytesOk`tBytesMalos`tHashOrigen`tHashDestino`tSerieVolumen`tRutaRelativa`tDestino`tMensaje`r`n", $script:Utf8ConBom)
    }
    if ($Identidad) {
        $json = $Identidad | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText((Join-Path $Caso 'trabajo.json'), $json, $script:Utf8ConBom)
    }
    return [pscustomobject]$dirs
}

function ConvertTo-CampoTsv {
    param($V)
    if ($null -eq $V) { return '' }
    return ([string]$V) -replace "[`t`r`n]", ' '
}

function Add-EntradaDiario {
    param($Item, [string]$Estado, [string]$Categoria, [string]$Estrategia, $R, [string]$Destino, [string]$Mensaje)
    $bytesOk = 0; $bytesMalos = 0; $ho = ''; $hd = ''
    if ($R) { $bytesOk = $R.bytesOk; $bytesMalos = $R.bytesMalos; $ho = $R.hashOrigen; $hd = $R.hashDestino }
    $campos = @((Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Item.Id, $Estado, $Categoria, $Item.Intentos, $Estrategia, $Item.Tamano, $bytesOk, $bytesMalos, $ho, $hd, $Item.Serie, $Item.Relativa, $Destino, $Mensaje)
    $linea = (($campos | ForEach-Object { ConvertTo-CampoTsv $_ }) -join "`t") + "`r`n"
    [System.IO.File]::AppendAllText($script:ArchivoDiario, $linea, $script:Utf8SinBom)
}

function Read-Diario {
    # Última entrada por Id (el diario es de solo añadir)
    param([string]$Ruta)
    $ultimo = @{}
    if (-not (Test-Path -LiteralPath $Ruta)) { return $ultimo }
    $lineas = [System.IO.File]::ReadAllLines($Ruta, [System.Text.Encoding]::UTF8)
    for ($i = 1; $i -lt $lineas.Length; $i++) {
        $p = $lineas[$i].Split("`t")
        if ($p.Length -lt 15) { continue }
        $ultimo[$p[1]] = [pscustomobject]@{ Fecha = $p[0]; Id = $p[1]; Estado = $p[2]; Categoria = $p[3]; Intento = $p[4]; Estrategia = $p[5]; Tamano = $p[6]
            BytesOk = $p[7]; BytesMalos = $p[8]; HashOrigen = $p[9]; HashDestino = $p[10]; Serie = $p[11]; Relativa = $p[12]; Destino = $p[13]; Mensaje = $p[14] }
    }
    return $ultimo
}

function Get-IdArchivo {
    # Identificador estable de un archivo dentro de un trabajo: serie del volumen + ruta relativa
    param([string]$Serie, [string]$Relativa)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($Serie + '|' + $Relativa).ToLowerInvariant()))
        return ([System.BitConverter]::ToString($b, 0, 8)).Replace('-', '')
    } finally { $sha.Dispose() }
}

# ---------------------------------------------------------------------------
# Prioridades (pliego, fase 3D)
# ---------------------------------------------------------------------------
function Get-PrioridadArchivo {
    param($Config, [string]$Nombre, [string]$Etiqueta, [string]$Tipo)
    $ext = [System.IO.Path]::GetExtension($Nombre).TrimStart('.').ToLowerInvariant()
    $i = 0
    foreach ($p in @($Config.Prioridades)) {
        $i++
        if ($p.Resto) { return [pscustomobject]@{ Nivel = $i; Nombre = [string]$p.Nombre } }
        if ($p.Tipos -and (@($p.Tipos) -contains $Tipo)) { return [pscustomobject]@{ Nivel = $i; Nombre = [string]$p.Nombre } }
        if ($p.Extensiones -and (@($p.Extensiones) -contains $ext)) { return [pscustomobject]@{ Nivel = $i; Nombre = [string]$p.Nombre } }
        if ($p.Carpetas) {
            foreach ($c in @($p.Carpetas)) { if ($Etiqueta -match ('(?i)(^|\\)' + [regex]::Escape([string]$c) + '$')) { return [pscustomobject]@{ Nivel = $i; Nombre = [string]$p.Nombre } } }
        }
    }
    return [pscustomobject]@{ Nivel = 999; Nombre = 'Resto' }
}

function New-ColaRecuperacion {
    <#
      Recorre las carpetas elegidas (solo lectura) y arma la cola priorizada.
      Lo que no se debe copiar en claro queda clasificado desde aquí:
        enlaces simbólicos y archivos con heurística de malware -> OMITIDO_POR_SEGURIDAD
        archivos que solo están en la nube -> ERROR_RECUPERACION (no están en el disco)
    #>
    param($Ctx, $Config)
    $cola = [System.Collections.Generic.List[object]]::new()
    $excluir = @($Ctx.Config.ExcluirCarpetasEnRespaldo | ForEach-Object { [string]$_ })
    foreach ($c in @($Ctx.Carpetas)) {
        $serie = Get-SerieVolumen -Letra $c.Origen
        $raizVol = $c.Origen.Substring(0, 2) + '\'   # 'Z:\' (el origen puede venir como 'Z:' si es la raíz)
        $raizRecorrido = $c.Origen
        if ($raizRecorrido -match '^[A-Za-z]:$') { $raizRecorrido += '\' }   # 'Z:' sin barra sería la carpeta actual de Z:
        Write-Log ("Recorriendo {0} ..." -f $raizRecorrido)
        foreach ($f in @(Get-ArchivosRecursivo -Raiz $raizRecorrido -Fase 'Cola' -ExcluirNombresCarpeta $excluir)) {
            $ruta = Get-RutaCorta $f.FullName
            $attr = [int]$f.Attributes
            $tam = [int64]0; try { $tam = $f.Length } catch { }
            $mod = ''; try { $mod = $f.LastWriteTimeUtc.ToString('o') } catch { }
            $relCarpeta = $ruta.Substring($c.Origen.TrimEnd('\').Length).TrimStart('\')
            $relVol = $ruta.Substring($raizVol.Length)
            $pri = Get-PrioridadArchivo -Config $Config -Nombre $f.Name -Etiqueta $c.Etiqueta -Tipo $c.Tipo
            $item = [pscustomobject]@{
                Id = (Get-IdArchivo -Serie $serie -Relativa $relVol); Ruta = $ruta; Relativa = $relVol; Serie = $serie
                Carpeta = $c.Etiqueta; RelCarpeta = $relCarpeta; Tamano = $tam; Modificado = $mod
                Prioridad = $pri.Nivel; Categoria = $pri.Nombre; Estado = 'PENDIENTE'; Motivo = ''; Intentos = 0; UltimoCodigo = -1
                Destino = ''; Resultado = $null; Pasada = 1
            }
            if (Test-SoloNube $attr) { $item.Estado = 'ERROR_RECUPERACION'; $item.Motivo = 'SOLO_EN_LA_NUBE: el contenido no está en el disco' }
            elseif (($attr -band $script:ATTR_REPARSE) -ne 0 -and (Test-EsEnlaceSimbolico -Ruta $ruta)) { $item.Estado = 'OMITIDO_POR_SEGURIDAD'; $item.Motivo = 'Enlace simbólico: no se sigue' }
            else {
                $hz = Test-HeuristicasArchivo -Ruta $ruta -Nombre $f.Name -Cabecera $null
                if ($hz -and $hz.Severidad -eq 'Alta') { $item.Estado = 'OMITIDO_POR_SEGURIDAD'; $item.Motivo = $hz.Motivo }
            }
            $cola.Add($item)
        }
    }
    $orden = [string]$Config.OrdenDentroDePrioridad
    $lista = $cola.ToArray()
    $signo = 1
    if ($orden -eq 'TamanoDescendente') { $signo = -1 }
    $lista = @($lista | Sort-Object -Property { [double]$_.Prioridad * 1e15 + $signo * [double]$_.Tamano })
    return $lista
}

# ---------------------------------------------------------------------------
# Extracción adaptativa (pliego, fases 3A-3D y 7)
# ---------------------------------------------------------------------------
function Resolve-RutaDestinoItem {
    # Concatenación simple (sin Join-Path/System.IO.Path): admite rutas de más de 260 caracteres
    param($Dirs, $Item, [string]$Base)
    return ($Base.TrimEnd('\') + '\' + ([string]$Item.Carpeta).Trim('\') + '\' + ([string]$Item.RelCarpeta).TrimStart('\'))
}

function Move-ArchivoRecuperado {
    param([string]$De, [string]$A)
    $corta = Get-RutaCorta $A
    $dir = $corta.Substring(0, $corta.LastIndexOf('\'))
    [void][System.IO.Directory]::CreateDirectory((Get-RutaLarga $dir))
    if ([System.IO.File]::Exists((Get-RutaLarga $A))) { [System.IO.File]::Delete((Get-RutaLarga $A)) }
    [System.IO.File]::Move((Get-RutaLarga $De), (Get-RutaLarga $A))
}

function Invoke-CopiaItem {
    param($Item, $Dirs, $Config, [switch]$Rapido)
    $enCurso = Join-Path $Dirs.EnCurso ($Item.Id + '.bin')
    $mapa = Join-Path $Dirs.Mapas ($Item.Id + '.map')
    $arg = @('copiar', '--origen', $Item.Ruta, '--destino', $enCurso, '--mapa', $mapa,
        '--bloque', [string]([int]$Config.BloqueKB * 1024), '--minimo', [string]([int]$Config.MinimoKB * 1024),
        '--reintentos', [string][int]$Config.Reintentos, '--espera-ms', [string][int]$Config.EsperaMs,
        '--max-errores', [string][int]$Config.MaxErroresFisicosPorArchivo, '--margen', [string]([int64]$Config.MargenLibreMB * 1MB))
    if ($Rapido) { $arg += @('--fase', 'rapida') }
    if ($Item.PSObject.Properties['PruebaFallos'] -and $Item.PruebaFallos) { $arg += @('--prueba-fallos', $Item.PruebaFallos) }
    if ($Item.PSObject.Properties['PruebaCortar'] -and $Item.PruebaCortar -ge 0) { $arg += @('--prueba-cortar-tras', [string]$Item.PruebaCortar) }
    $r = Invoke-Motor -Argumentos $arg
    return $r
}

function Invoke-ColaRecuperacion {
    <#
      Procesa la cola: copia adaptativa, clasificación de cada fallo, estrategia
      por categoría, reintentos limitados, cola de pendientes y diario.
      Devuelve un resumen. Reanudable: lo terminado (y verificado) no se repite.
    #>
    param($Cola, $Dirs, $Config, [string]$Destino, [switch]$ModoFallo)
    $max = [Math]::Max(1, [int]$Config.MaxIntentosPorArchivo)
    $umbral = [Math]::Max(1, [int]$Config.UmbralArchivosConFalloFisico)
    $conFisico = 0
    $estrategias = [System.Collections.Generic.List[string]]::new()
    $abortar = $null
    $segunda = [System.Collections.Generic.List[object]]::new()
    $pend = [System.Collections.Generic.Queue[object]]::new()
    foreach ($it in $Cola) { if ($it.Estado -eq 'PENDIENTE') { $pend.Enqueue($it) } }
    $total = $pend.Count; $hechos = 0
    $enModoFallo = [bool]$ModoFallo
    if ($enModoFallo) { $estrategias.Add('Modo de fallo físico desde el inicio (salud del disco dudosa o mala)') }

    # Lo omitido por seguridad se cifra en cuarentena (nunca se copia en claro)
    foreach ($it in $Cola) {
        if ($it.Estado -eq 'OMITIDO_POR_SEGURIDAD' -and $it.Motivo -notlike 'Enlace*' -and -not $it.Destino) {
            try {
                $q = Join-Path $Dirs.Cuarentena ('B' + $it.Id + '.cuar')
                $cif = Protect-ArchivoCuarentena -Origen $it.Ruta -Destino $q
                $it.Destino = $q
                Write-Log ("Cuarentena (cifrado {0}): {1} - {2}" -f $cif, $it.Ruta, $it.Motivo) -Nivel DET
            } catch { $it.Motivo += ' | no se pudo copiar a cuarentena: ' + $_.Exception.Message }
            Add-EntradaDiario -Item $it -Estado $it.Estado -Categoria 'SEGURIDAD' -Estrategia 'cuarentena cifrada' -R $null -Destino $it.Destino -Mensaje $it.Motivo
        } elseif ($it.Estado -eq 'ERROR_RECUPERACION' -and $it.Motivo -like 'SOLO_EN_LA_NUBE*' -and -not $it.Destino) {
            $it.Destino = '-'
            Add-EntradaDiario -Item $it -Estado $it.Estado -Categoria 'NO_ESTA_EN_EL_DISCO' -Estrategia 'ninguna' -R $null -Destino '' -Mensaje $it.Motivo
        }
    }

    while ($pend.Count -gt 0) {
        $it = $pend.Dequeue()
        $it.Intentos++
        # Espacio antes de cada archivo: si no cabe, se sigue con otros
        $libre = Get-EspacioLibre $Destino
        $margen = [int64]$Config.MargenLibreMB * 1MB
        if ($libre -lt ($it.Tamano + $margen)) {
            $it.Estado = 'PENDIENTE'; $it.Motivo = 'DESTINO_SIN_ESPACIO'
            Add-EntradaDiario -Item $it -Estado 'PENDIENTE' -Categoria 'DESTINO_SIN_ESPACIO' -Estrategia 'omitir y seguir' -R $null -Destino '' -Mensaje ('libre {0}' -f (Format-Bytes ([double]$libre)))
            if (-not $estrategias.Contains('DESTINO_SIN_ESPACIO')) { $estrategias.Add('DESTINO_SIN_ESPACIO') }
            continue
        }
        # Disco con fallos: primera pasada rápida para todos; lo parcial se completa al final
        $rapido = ($enModoFallo -and $it.Pasada -lt 2)
        $r = Invoke-CopiaItem -Item $it -Dirs $Dirs -Config $Config -Rapido:$rapido
        $it.Resultado = $r
        $cat = [string]$r.categoria
        $hechos++
        if ($r.fisico) { $conFisico++ }
        if (-not $enModoFallo -and $conFisico -ge $umbral) {
            $enModoFallo = $true
            $estrategias.Add(('Modo de fallo físico activado tras {0} archivos con errores de lectura repetidos' -f $conFisico))
            Write-Log 'El disco muestra fallos físicos: se pasa a primera pasada rápida para todo lo que queda (sin insistir en zonas malas).' -Nivel AVISO
        }
        $estr = [string]$r.estrategia
        $estado = [string]$r.estado
        $enCurso = Join-Path $Dirs.EnCurso ($it.Id + '.bin')
        switch ($estado) {
            'RECUPERADO_INTEGRO' {
                $dest = Resolve-RutaDestinoItem -Dirs $Dirs -Item $it -Base $Dirs.Respaldo
                Move-ArchivoRecuperado -De $enCurso -A $dest
                $it.Estado = $estado; $it.Destino = $dest
            }
            'RECUPERADO_SIN_VERIFICACION_COMPLETA' {
                $dest = Resolve-RutaDestinoItem -Dirs $Dirs -Item $it -Base $Dirs.Respaldo
                Move-ArchivoRecuperado -De $enCurso -A $dest
                $it.Estado = $estado; $it.Destino = $dest
            }
            'RECUPERADO_PARCIAL' {
                if ($rapido -and $it.Pasada -lt 2 -and $it.Intentos -lt $max) {
                    # Se completa en una segunda pasada al final, cuando ya se rescató lo legible de todo
                    $it.Pasada = 2; $segunda.Add($it); $it.Estado = 'PENDIENTE'; $it.Motivo = 'segunda pasada'
                } else {
                    $dest = Resolve-RutaDestinoItem -Dirs $Dirs -Item $it -Base $Dirs.Parciales
                    Move-ArchivoRecuperado -De $enCurso -A $dest
                    $it.Estado = $estado; $it.Destino = $dest
                }
                if (-not $estrategias.Contains('ARCHIVO_PARCIALMENTE_LEGIBLE')) { $estrategias.Add('ARCHIVO_PARCIALMENTE_LEGIBLE') }
            }
            'PENDIENTE' {
                $it.Estado = 'PENDIENTE'; $it.Motivo = $cat
                if ($cat -eq 'DISPOSITIVO_DESCONECTADO') { $abortar = 'El disco de origen dejó de responder (desconectado).' }
                if ($cat -eq 'ERROR_DESTINO' -or $cat -eq 'DESTINO_SIN_ESPACIO') { if (-not $estrategias.Contains('DESTINO_SIN_ESPACIO')) { $estrategias.Add('DESTINO_SIN_ESPACIO') } }
            }
            default {
                # ERROR_RECUPERACION u otros: estrategia según la categoría
                $repetido = ($it.UltimoCodigo -eq [int]$r.codigoWin32)
                $it.UltimoCodigo = [int]$r.codigoWin32
                $reintentar = $false
                if ($it.Intentos -lt $max -and -not $repetido) {
                    if ($cat -eq 'ARCHIVO_INACCESIBLE' -and @(32, 33) -contains [int]$r.codigoWin32) { $reintentar = $true }
                    if ($cat -eq 'ERROR_INTEGRIDAD') {
                        $reintentar = $true
                        foreach ($x in @($enCurso, (Join-Path $Dirs.Mapas ($it.Id + '.map')))) { if (Test-Path -LiteralPath $x) { Remove-Item -LiteralPath $x -Force } }
                    }
                }
                if ($reintentar) {
                    $pend.Enqueue($it); $it.Estado = 'PENDIENTE'; $it.Motivo = ('reintento por ' + $cat)
                    if (-not $estrategias.Contains($cat)) { $estrategias.Add($cat) }
                } else {
                    $it.Estado = 'ERROR_RECUPERACION'; $it.Motivo = ('{0}: {1}' -f $cat, $r.mensaje)
                    if (Test-Path -LiteralPath $enCurso) { Remove-Item -LiteralPath $enCurso -Force -ErrorAction SilentlyContinue }
                    if ($cat -and -not $estrategias.Contains($cat)) { $estrategias.Add($cat) }
                }
            }
        }
        if ($estr -like 'backup_semantics*' -and -not $estrategias.Contains('PROBLEMA_PERMISOS')) { $estrategias.Add('PROBLEMA_PERMISOS') }
        $catDiario = $cat; if (-not $catDiario) { $catDiario = '-' }
        Add-EntradaDiario -Item $it -Estado $it.Estado -Categoria $catDiario -Estrategia $estr -R $r -Destino $it.Destino -Mensaje ([string]$r.mensaje + ' ' + $it.Motivo)
        $color = 'Gray'
        if ($it.Estado -eq 'RECUPERADO_INTEGRO') { $color = 'Green' } elseif ($it.Estado -like 'RECUPERADO*') { $color = 'Yellow' } elseif ($it.Estado -eq 'ERROR_RECUPERACION') { $color = 'Red' }
        Write-Host ('  [{0}/{1}] {2,-36} {3}' -f $hechos, $total, $it.Estado, $it.Relativa) -ForegroundColor $color
        if ($abortar) { break }
        if ($pend.Count -eq 0 -and $segunda.Count -gt 0) {
            # Segunda pasada: solo lo que quedó parcial, con todas las técnicas (o rápida si el disco falla)
            Write-Log ("Segunda pasada sobre {0} archivos parciales." -f $segunda.Count)
            if (-not $estrategias.Contains('Segunda pasada sobre archivos parciales')) { $estrategias.Add('Segunda pasada sobre archivos parciales') }
            foreach ($x in $segunda) { $pend.Enqueue($x) }
            $total += $segunda.Count
            $segunda.Clear()
        }
    }
    if ($abortar) { Write-Log $abortar -Nivel ERROR }
    return [pscustomobject]@{ Estrategias = $estrategias.ToArray(); ModoFallo = $enModoFallo; Abortado = $abortar }
}

function Restore-EstadoDesdeDiario {
    <#
      Reanudación: aplica el diario de un trabajo anterior a la cola nueva.
      Un archivo solo se da por recuperado si su copia sigue existiendo y su
      SHA-256 coincide con el registrado; si no, vuelve a la cola.
    #>
    param($Cola, [string]$RutaDiario, $Dirs)
    $d = Read-Diario -Ruta $RutaDiario
    $n = 0; $revisados = 0; $reencolados = 0
    foreach ($it in $Cola) {
        if (-not $d.ContainsKey($it.Id)) { continue }
        $e = $d[$it.Id]
        $n++
        if ($e.Estado -eq 'RECUPERADO_PARCIAL' -and $Dirs -and $e.Destino -and (Test-ArchivoExiste $e.Destino) -and (Test-Path -LiteralPath (Join-Path $Dirs.Mapas ($it.Id + '.map')))) {
            # Parcial con mapa: se reintenta SOLO lo que faltaba (la copia vuelve a "en curso")
            Move-ArchivoRecuperado -De $e.Destino -A (Join-Path $Dirs.EnCurso ($it.Id + '.bin'))
            $it.Pasada = 2; $it.Intentos = [int]$e.Intento; $it.Motivo = 'reintento de las zonas ilegibles'
            $reencolados++
            continue
        }
        if ($script:EstadosFinales -contains $e.Estado -and $e.Destino -and $e.Destino -ne '-' -and $e.Estado -like 'RECUPERADO*') {
            $revisados++
            $okHash = $false
            try { if ((Test-ArchivoExiste $e.Destino) -and $e.HashDestino -and (Get-Sha256Archivo -Ruta $e.Destino).Hash -eq $e.HashDestino) { $okHash = $true } } catch { }
            if ($okHash -and [int64]$e.Tamano -eq $it.Tamano) { $it.Estado = $e.Estado; $it.Destino = $e.Destino; $it.Motivo = 'verificado al reanudar'; $it.Intentos = [int]$e.Intento }
            else { $reencolados++; $it.Motivo = 'la copia anterior no coincide: se repite' }
        } elseif ($e.Estado -eq 'OMITIDO_POR_SEGURIDAD' -or ($e.Estado -eq 'ERROR_RECUPERACION' -and $e.Categoria -ne 'ARCHIVO_INACCESIBLE')) {
            $it.Estado = $e.Estado; $it.Destino = $e.Destino; $it.Motivo = $e.Mensaje; $it.Intentos = [int]$e.Intento
        }
        # PENDIENTE: se reintenta (el mapa y la copia en curso, si existen, se continúan)
    }
    return [pscustomobject]@{ ConEntrada = $n; Revisados = $revisados; Reencolados = $reencolados }
}

# ---------------------------------------------------------------------------
# Imagen, VHD, particiones y firmas
# ---------------------------------------------------------------------------
function Mount-ImagenSoloLectura {
    # Conecta un VHD en SOLO LECTURA y devuelve el número de disco y sus letras
    param([string]$Vhd)
    $antes = @(Get-ListaDiscosDp | ForEach-Object { $_.Number })
    $r = Invoke-Diskpart @(('select vdisk file="{0}"' -f $Vhd), 'attach vdisk readonly')
    Write-Log ('attach vdisk: ' + (($r | Where-Object { $_ }) -join ' | ')) -SoloArchivo
    Start-Sleep -Seconds 3
    $nuevos = @(Get-ListaDiscosDp | Where-Object { $antes -notcontains $_.Number })
    if ($nuevos.Count -ne 1) { throw 'No se pudo identificar el disco de la imagen conectada.' }
    $n = [int]$nuevos[0].Number
    $d = Get-DetalleDiscoDp -Numero $n
    if ($d.IsOffline) {
        # Política SAN de WinPE (o colisión de firma): se pone en línea; sigue en solo lectura
        $r2 = Invoke-Diskpart @("select disk $n", 'online disk noerr')
        Write-Log ('online imagen: ' + (($r2 | Where-Object { $_ }) -join ' | ')) -SoloArchivo
        Start-Sleep -Seconds 2
    }
    for ($i = 0; $i -lt 5 -and @((Get-DetalleDiscoDp -Numero $n).Volumenes).Count -eq 0; $i++) { Start-Sleep -Seconds 2 }
    Add-LetrasVolumenesDp -Numero $n
    Start-Sleep -Seconds 2
    return [pscustomobject]@{ Disco = $n; Letras = @(Get-LetrasDeDisco -Numero $n); SoloLectura = (Test-DiscoSoloLectura -Numero $n) }
}

function Dismount-Imagen {
    param([string]$Vhd)
    [void](Invoke-Diskpart @(('select vdisk file="{0}"' -f $Vhd), 'detach vdisk noerr'))
}

function Export-ResultadosCsv {
    param($Cola, [string]$Ruta)
    $filas = [System.Collections.Generic.List[object]]::new()
    foreach ($it in @($Cola)) {
        $ho = ''; $hd = ''; $ok = ''; $malos = ''; $estr = ''
        if ($it.Resultado) { $ho = [string]$it.Resultado.hashOrigen; $hd = [string]$it.Resultado.hashDestino; $ok = $it.Resultado.bytesOk; $malos = $it.Resultado.bytesMalos; $estr = [string]$it.Resultado.estrategia }
        $filas.Add([pscustomobject]@{ Id = $it.Id; Estado = $it.Estado; Prioridad = $it.Prioridad; Categoria = $it.Categoria; Ruta = $it.Ruta; Tamano = $it.Tamano
            Modificado = $it.Modificado; Intentos = $it.Intentos; Estrategia = $estr; BytesOk = $ok; BytesIlegibles = $malos; SHA256Origen = $ho; SHA256Copia = $hd; Destino = $it.Destino; Motivo = $it.Motivo })
    }
    Export-ListaCsv -Ruta $Ruta -Objetos $filas -Columnas @('Id', 'Estado', 'Prioridad', 'Categoria', 'Ruta', 'Tamano', 'Modificado', 'Intentos', 'Estrategia', 'BytesOk', 'BytesIlegibles', 'SHA256Origen', 'SHA256Copia', 'Destino', 'Motivo')
}

# ---------------------------------------------------------------------------
# Informe (pliego, fase 8): hechos comprobados / parciales / inciertos
# ---------------------------------------------------------------------------
function New-ReporteBlackbox {
    param($Ctx, $Info, $Dirs, [DateTime]$Inicio, [bool]$Abortado, [string]$Huella, [string]$IntegridadInicial, [string]$IntegridadFinal)
    $cola = @($Info.Cola)
    $cuenta = [ordered]@{}
    foreach ($e in @('RECUPERADO_INTEGRO', 'RECUPERADO_PARCIAL', 'RECUPERADO_SIN_VERIFICACION_COMPLETA', 'ERROR_RECUPERACION', 'OMITIDO_POR_SEGURIDAD', 'PENDIENTE')) { $cuenta[$e] = 0 }
    $bytesRec = [int64]0; $bytesMalos = [int64]0
    $errCat = @{}
    foreach ($it in $cola) {
        if ($cuenta.Contains($it.Estado)) { $cuenta[$it.Estado]++ } else { $cuenta['PENDIENTE']++ }
        if ($it.Estado -like 'RECUPERADO*' -and $it.Resultado) { $bytesRec += [int64]$it.Resultado.bytesOk; $bytesMalos += [int64]$it.Resultado.bytesMalos }
        elseif ($it.Estado -like 'RECUPERADO*') { $bytesRec += [int64]$it.Tamano }
        if ($it.Estado -eq 'ERROR_RECUPERACION' -or $it.Estado -eq 'PENDIENTE') {
            $c = ([string]$it.Motivo).Split(':')[0]
            if (-not $c) { $c = 'SIN_PROCESAR' }
            if ($errCat.ContainsKey($c)) { $errCat[$c]++ } else { $errCat[$c] = 1 }
        }
    }
    $total = $cola.Count
    $nFirmas = 0; if ($Info.Firmas) { $nFirmas = [int]$Info.Firmas.hallados }

    # Veredicto
    $nivel = 'VERDE'; $color = 'Green'
    $resumen = ('{0} de {1} archivos recuperados íntegros (SHA-256 verificado).' -f $cuenta['RECUPERADO_INTEGRO'], $total)
    if ($Abortado -or $Info.Abortado) { $nivel = 'ROJO'; $color = 'Red'; $resumen = 'El trabajo se detuvo antes de terminar: es reanudable. ' + $resumen }
    elseif ($cuenta['ERROR_RECUPERACION'] -gt 0 -or $cuenta['RECUPERADO_PARCIAL'] -gt 0 -or $cuenta['PENDIENTE'] -gt 0) { $nivel = 'AMARILLO'; $color = 'Yellow' }
    if ($total -eq 0 -and $nFirmas -gt 0) { $resumen = ('{0} archivos recuperados por firma (sin nombres originales).' -f $nFirmas) }
    if ($total -eq 0 -and $Info.Imagen) { $resumen = ('Imagen: {0} ({1} leídos, {2} ilegibles).' -f $Info.Imagen.Resultado.estado, (Format-Bytes ([double]$Info.Imagen.Resultado.bytesOk)), (Format-Bytes ([double]$Info.Imagen.Resultado.bytesMalos))) + ' ' + $resumen }

    $hechos = [System.Collections.Generic.List[string]]::new()
    $parciales = [System.Collections.Generic.List[string]]::new()
    $inciertos = [System.Collections.Generic.List[string]]::new()
    if ($Info.Seguridad) { foreach ($c in $Info.Seguridad.Comprobaciones) { if ($c.Ok) { $hechos.Add(('{0}: {1}' -f $c.Comprobacion, $c.Detalle)) } } }
    $hechos.Add(('{0} archivos con copia idéntica al original (SHA-256 del origen = SHA-256 de la copia).' -f $cuenta['RECUPERADO_INTEGRO']))
    if ($cuenta['OMITIDO_POR_SEGURIDAD'] -gt 0) { $hechos.Add(('{0} archivos NO se copiaron en claro por seguridad (cuarentena cifrada o enlace no seguido).' -f $cuenta['OMITIDO_POR_SEGURIDAD'])) }
    if ($cuenta['RECUPERADO_PARCIAL'] -gt 0) { $parciales.Add(('{0} archivos recuperados en parte: las zonas ilegibles ({1}) quedaron en ceros; su mapa está en Mapas\ y se puede reintentar.' -f $cuenta['RECUPERADO_PARCIAL'], (Format-Bytes ([double]$bytesMalos)))) }
    if ($cuenta['RECUPERADO_SIN_VERIFICACION_COMPLETA'] -gt 0) { $parciales.Add(('{0} archivos copiados enteros pero sin poder releer el original para comparar el SHA-256.' -f $cuenta['RECUPERADO_SIN_VERIFICACION_COMPLETA'])) }
    if ($Info.Imagen -and -not $Info.Imagen.Completa) { $parciales.Add('La imagen del disco está incompleta: ver su mapa (zonas "-" ilegibles, "?" sin leer).') }
    if ($Info.Firmas -and $nFirmas -eq 0) { $inciertos.Add('La búsqueda por firmas no encontró archivos. Eso no prueba que no existan: pueden estar fragmentados, sobrescritos o ser de tipos que no se buscan.') }
    if ($nFirmas -gt 0) { $inciertos.Add(('{0} archivos recuperados por firma: sin nombres ni carpetas; si estaban fragmentados en el disco pueden estar dañados aunque "estructuraCompleta" diga true. No hay original con el que comparar.' -f $nFirmas)) }
    if ($cuenta['PENDIENTE'] -gt 0) { $inciertos.Add(('{0} archivos quedaron PENDIENTES (sin espacio, interrupción o desconexión): no se sabe aún si se pueden recuperar.' -f $cuenta['PENDIENTE'])) }
    $vs = [string]$Info.Salud.Veredicto
    if ($Info.SaludMotor -and $Info.SaludMotor.veredicto) { $vs = [string]$Info.SaludMotor.veredicto }
    if ($vs -eq 'DESCONOCIDO' -or -not $vs) { $inciertos.Add('No se pudo leer la salud (SMART) del disco: no se descarta un fallo físico.') }
    if ($Info.ClamAV -notlike '*escaneados*') { $inciertos.Add('Lo recuperado no se analizó con antivirus en TITAN: analícelo con Defender en un PC sano antes de abrirlo.') }

    $rec = [System.Collections.Generic.List[string]]::new()
    if ($cuenta['RECUPERADO_PARCIAL'] -gt 0) { $rec.Add('Para los archivos parciales: reanude el trabajo más adelante (otra pasada sobre las zonas malas) o haga una imagen del disco en un disco externo y recupere desde la imagen.') }
    if ($cuenta['PENDIENTE'] -gt 0) { $rec.Add('Hay archivos pendientes: libere espacio en TITAN (o use un disco externo como destino) y reanude el trabajo.') }
    if ($vs -eq 'MALO' -or $vs -eq 'DUDOSO') { $rec.Add('El disco muestra señales de fallo: no lo use más que para rescatar datos; si son importantes, considere un laboratorio de recuperación antes de insistir.') }
    if ($Info.Diagnostico | Where-Object { $_.Estado -eq 'VOLUMEN_BLOQUEADO' }) { $rec.Add('Hay un volumen BitLocker bloqueado: busque la clave de recuperación (48 dígitos) en account.microsoft.com/devices/recoverykey y repita. Sin la clave, el contenido no es recuperable.') }
    if ($Info.Diagnostico | Where-Object { $_.Estado -eq 'VOLUMEN_NO_RECONOCIDO' }) { $rec.Add('Hay un volumen no reconocido: use la búsqueda de particiones sobre una imagen y, si no aparece, la recuperación por firmas.') }
    $rec.Add('Antes de abrir lo recuperado, analícelo con Microsoft Defender en un PC sano. No lo abra en el equipo dañado.')
    $rec.Add('Guarde la carpeta del trabajo completa (Datos, Mapas, Registros): permite reanudar y demuestra con hashes que las copias no cambiaron.')

    # ---------------- TXT ----------------
    $t = [System.Collections.Generic.List[string]]::new()
    $t.Add('TITAN BLACKBOX - INFORME DE RECUPERACIÓN AVANZADA'); $t.Add('=' * 60)
    $t.Add(('Fecha: {0}   Duración: {1}   Reanudado: {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), (Format-Duracion ((Get-Date) - $Inicio)), $Info.Reanudado))
    $t.Add(('VEREDICTO ({0}): {1}' -f $nivel, $resumen)); $t.Add('')
    $t.Add('EQUIPO Y DISPOSITIVO'); $t.Add('--------------------')
    $t.Add(('Equipo: {0} | {1} {2} (build {3})' -f $Ctx.Sistema.Nombre, $Ctx.Sistema.Producto, $Ctx.Sistema.Version, $Ctx.Sistema.Build))
    if ($Ctx.DiscoInfo) { $t.Add(('Disco: #{0} {1} | {2} | bus {3} | id {4}' -f $Ctx.DiscoObjetivo, $Ctx.DiscoInfo.FriendlyName, (Format-Bytes ([double]$Ctx.DiscoInfo.Size)), $Ctx.DiscoInfo.BusType, $Ctx.DiscoInfo.Id)) }
    foreach ($v in @($Info.Diagnostico)) { $t.Add(('  Volumen {0} {1} {2} {3} -> {4} | BitLocker: {5} | serie {6}' -f $v.Num, $v.Letra, $v.Fs, (Format-Bytes ([double]$v.Tamano)), $v.Estado, $v.BitLocker, $v.Serie)) }
    $t.Add(('Salud: {0} | Secure Boot: {1}' -f $vs, $Info.SecureBoot))
    if ($Info.SaludMotor -and $Info.SaludMotor.PSObject.Properties['desgastePct']) { $t.Add(('  NVMe: desgaste {0}%, reserva {1}%, errores de integridad {2}, horas {3}, apagados inseguros {4}' -f $Info.SaludMotor.desgastePct, $Info.SaludMotor.reservaDisponiblePct, $Info.SaludMotor.erroresIntegridadMedio, $Info.SaludMotor.horasEncendido, $Info.SaludMotor.apagadosInseguros)) }
    $t.Add('')
    $t.Add('ARCHIVOS'); $t.Add('--------')
    $t.Add(('Encontrados: {0}' -f $total))
    foreach ($k in $cuenta.Keys) { $t.Add(('  {0,-38} {1}' -f $k, $cuenta[$k])) }
    $t.Add(('Bytes recuperados: {0} | ilegibles en archivos parciales: {1}' -f (Format-Bytes ([double]$bytesRec)), (Format-Bytes ([double]$bytesMalos))))
    if ($nFirmas -gt 0) { $t.Add(('Recuperados por firma: {0}' -f $nFirmas)) }
    $t.Add('')
    $t.Add('HECHOS COMPROBADOS'); foreach ($x in $hechos) { $t.Add('  - ' + $x) }
    $t.Add('RESULTADOS PARCIALES'); if ($parciales.Count -eq 0) { $t.Add('  (ninguno)') } else { foreach ($x in $parciales) { $t.Add('  - ' + $x) } }
    $t.Add('CONCLUSIONES INCIERTAS'); if ($inciertos.Count -eq 0) { $t.Add('  (ninguna)') } else { foreach ($x in $inciertos) { $t.Add('  - ' + $x) } }
    $t.Add('')
    $t.Add('ERRORES POR CATEGORÍA'); foreach ($k in $errCat.Keys) { $t.Add(('  {0,-34} {1}  -> estrategia: {2}' -f $k, $errCat[$k], $script:EstrategiaPorCategoria[$k])) }
    $t.Add('ESTRATEGIAS APLICADAS'); foreach ($x in @($Info.Estrategias.ToArray() | Select-Object -Unique)) { $t.Add('  - ' + $x) }
    $t.Add('HERRAMIENTAS'); foreach ($x in $Info.Herramientas) { $t.Add('  - ' + $x) }
    $t.Add(('  - Antivirus sobre lo recuperado: {0}' -f $Info.ClamAV))
    if ($Info.Imagen) { $t.Add(('IMAGEN: {0} -> {1} | {2} | mapa {3}' -f $Info.Imagen.Objeto, $Info.Imagen.Archivo, $Info.Imagen.Resultado.estado, $Info.Imagen.Mapa)) }
    if ($Info.Particiones) {
        $t.Add(('PARTICIONES: tabla {0}' -f $Info.Particiones.estilo))
        foreach ($h in @($Info.Particiones.halladas)) { $t.Add(('  {0} en {1} ({2}) en la tabla: {3}' -f $h.fs, (Format-Bytes ([double]$h.inicioBytes)), (Format-Bytes ([double]$h.bytes)), $h.enTabla)) }
    }
    $t.Add(('VERIFICACIÓN: SHA-256 del origen (leído durante la copia, o releído si hubo reintentos) contra SHA-256 de la copia. Integridad de TITAN: inicio {0}, final {1}. Huella {2}.' -f $IntegridadInicial, $IntegridadFinal, $Huella))
    $t.Add('Hashes y estado de cada archivo: Datos\resultado_archivos.csv y Datos\diario.tsv (historial de cada intento).')
    $pend = @($cola | Where-Object { $_.Estado -eq 'PENDIENTE' -or $_.Estado -eq 'ERROR_RECUPERACION' })
    if ($pend.Count -gt 0) { $t.Add('PENDIENTES Y ERRORES (primeros 100)'); foreach ($x in ($pend | Select-Object -First 100)) { $t.Add(('  [{0}] {1} - {2}' -f $x.Estado, $x.Relativa, $x.Motivo)) } }
    $t.Add('RECOMENDACIONES'); $k = 1; foreach ($x in $rec) { $t.Add(('{0}. {1}' -f $k, $x)); $k++ }
    foreach ($x in $Info.Avisos) { $t.Add('AVISO: ' + $x) }
    [System.IO.File]::WriteAllLines((Join-Path $Dirs.Reporte 'reporte.txt'), $t.ToArray(), $script:Utf8ConBom)

    # ---------------- HTML ----------------
    $h = New-Object System.Text.StringBuilder
    $colorV = '#1a7f37'; if ($nivel -eq 'ROJO') { $colorV = '#c62828' } elseif ($nivel -eq 'AMARILLO') { $colorV = '#b26a00' }
    [void]$h.AppendLine('<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$h.AppendLine('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''">')
    [void]$h.AppendLine('<title>TITAN BLACKBOX</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f5f7;color:#1d1d1f}main{max-width:1100px;margin:0 auto;padding:16px}h2{font-size:1.15em;border-bottom:2px solid #d0d7de;padding-bottom:4px;margin-top:26px}table{border-collapse:collapse;width:100%;background:#fff;font-size:.85em}th,td{border:1px solid #d0d7de;padding:5px;text-align:left;vertical-align:top;word-break:break-all}th{background:#eef1f4}.ver{color:#fff;padding:14px;border-radius:8px;font-weight:600}.t{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}.t div{background:#fff;border-radius:8px;padding:10px}.t b{display:block;font-size:1.4em}.nota{color:#555;font-size:.85em}</style></head><body><main>')
    [void]$h.AppendLine('<h1>TITAN BLACKBOX — recuperación avanzada</h1>')
    [void]$h.AppendLine(('<div class="ver" style="background:{0}">{1}</div>' -f $colorV, (ConvertTo-HtmlSeguro $resumen)))
    [void]$h.AppendLine('<h2>Resultado</h2><div class="t">')
    foreach ($par in @(@('Encontrados', $total), @('Íntegros', $cuenta['RECUPERADO_INTEGRO']), @('Parciales', $cuenta['RECUPERADO_PARCIAL']), @('Sin verificación completa', $cuenta['RECUPERADO_SIN_VERIFICACION_COMPLETA']), @('No recuperados', $cuenta['ERROR_RECUPERACION']), @('Omitidos por seguridad', $cuenta['OMITIDO_POR_SEGURIDAD']), @('Pendientes', $cuenta['PENDIENTE']), @('Bytes recuperados', (Format-Bytes ([double]$bytesRec))), @('Por firma', $nFirmas))) {
        [void]$h.AppendLine(('<div>{0}<b>{1}</b></div>' -f (ConvertTo-HtmlSeguro $par[0]), (ConvertTo-HtmlSeguro $par[1])))
    }
    [void]$h.AppendLine('</div>')
    foreach ($sec in @(@('Hechos comprobados', $hechos), @('Resultados parciales', $parciales), @('Conclusiones inciertas', $inciertos))) {
        [void]$h.AppendLine(('<h2>{0}</h2><ul>' -f $sec[0]))
        if ($sec[1].Count -eq 0) { [void]$h.AppendLine('<li>(ninguno)</li>') }
        foreach ($x in $sec[1]) { [void]$h.AppendLine(('<li>{0}</li>' -f (ConvertTo-HtmlSeguro $x))) }
        [void]$h.AppendLine('</ul>')
    }
    [void]$h.AppendLine('<h2>Equipo, disco y volúmenes</h2><table><tr><th>Dato</th><th>Valor</th></tr>')
    [void]$h.AppendLine(('<tr><td>Equipo</td><td>{0}</td></tr>' -f (ConvertTo-HtmlSeguro ('{0} | {1} {2} (build {3})' -f $Ctx.Sistema.Nombre, $Ctx.Sistema.Producto, $Ctx.Sistema.Version, $Ctx.Sistema.Build))))
    if ($Ctx.DiscoInfo) { [void]$h.AppendLine(('<tr><td>Disco</td><td>{0}</td></tr>' -f (ConvertTo-HtmlSeguro ('#{0} {1} | {2} | {3} | id {4}' -f $Ctx.DiscoObjetivo, $Ctx.DiscoInfo.FriendlyName, (Format-Bytes ([double]$Ctx.DiscoInfo.Size)), $Ctx.DiscoInfo.BusType, $Ctx.DiscoInfo.Id)))) }
    [void]$h.AppendLine(('<tr><td>Salud</td><td>{0}</td></tr>' -f (ConvertTo-HtmlSeguro $vs)))
    [void]$h.AppendLine('</table><table><tr><th>Vol.</th><th>Letra</th><th>Sistema</th><th>Tamaño</th><th>Estado</th><th>BitLocker</th><th>Serie</th></tr>')
    foreach ($v in @($Info.Diagnostico)) { [void]$h.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f $v.Num, (ConvertTo-HtmlSeguro $v.Letra), (ConvertTo-HtmlSeguro $v.Fs), (Format-Bytes ([double]$v.Tamano)), (ConvertTo-HtmlSeguro $v.Estado), (ConvertTo-HtmlSeguro $v.BitLocker), (ConvertTo-HtmlSeguro $v.Serie))) }
    [void]$h.AppendLine('</table>')
    [void]$h.AppendLine('<h2>Errores y estrategias</h2><table><tr><th>Categoría</th><th>Archivos</th><th>Estrategia aplicada</th></tr>')
    foreach ($k in $errCat.Keys) { [void]$h.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-HtmlSeguro $k), $errCat[$k], (ConvertTo-HtmlSeguro $script:EstrategiaPorCategoria[$k]))) }
    [void]$h.AppendLine('</table><ul>')
    foreach ($x in @($Info.Estrategias.ToArray() | Select-Object -Unique)) { [void]$h.AppendLine(('<li>{0}</li>' -f (ConvertTo-HtmlSeguro $x))) }
    [void]$h.AppendLine('</ul><h2>Herramientas</h2><ul>')
    foreach ($x in $Info.Herramientas) { [void]$h.AppendLine(('<li>{0}</li>' -f (ConvertTo-HtmlSeguro $x))) }
    [void]$h.AppendLine(('<li>Antivirus sobre lo recuperado: {0}</li></ul>' -f (ConvertTo-HtmlSeguro $Info.ClamAV)))
    [void]$h.AppendLine('<h2>Archivos (primeros 300; todos en Datos\resultado_archivos.csv)</h2><table><tr><th>Estado</th><th>Prioridad</th><th>Archivo</th><th>Tamaño</th><th>SHA-256 copia</th><th>Detalle</th></tr>')
    foreach ($it in ($cola | Sort-Object Prioridad | Select-Object -First 300)) {
        $hd = ''; if ($it.Resultado) { $hd = [string]$it.Resultado.hashDestino }
        [void]$h.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f (ConvertTo-HtmlSeguro $it.Estado), (ConvertTo-HtmlSeguro $it.Categoria), (ConvertTo-HtmlSeguro $it.Relativa), (Format-Bytes ([double]$it.Tamano)), (ConvertTo-HtmlSeguro $hd), (ConvertTo-HtmlSeguro $it.Motivo)))
    }
    [void]$h.AppendLine('</table><h2>Verificación</h2>')
    [void]$h.AppendLine(('<p>{0}</p>' -f (ConvertTo-HtmlSeguro ('SHA-256 del origen contra SHA-256 de la copia; un archivo solo es "íntegro" si el original se leyó completo y ambos coinciden. Integridad de TITAN: inicio {0}, final {1}. Huella {2}.' -f $IntegridadInicial, $IntegridadFinal, $Huella))))
    if ($Info.Imagen) { [void]$h.AppendLine(('<h2>Imagen</h2><p>{0}</p>' -f (ConvertTo-HtmlSeguro ('{0} -> {1}: {2}; leídos {3}, ilegibles {4}, sin leer {5}. Mapa: {6}' -f $Info.Imagen.Objeto, $Info.Imagen.Archivo, $Info.Imagen.Resultado.estado, (Format-Bytes ([double]$Info.Imagen.Resultado.bytesOk)), (Format-Bytes ([double]$Info.Imagen.Resultado.bytesMalos)), (Format-Bytes ([double]$Info.Imagen.Resultado.bytesPendientes)), $Info.Imagen.Mapa)))) }
    [void]$h.AppendLine('<h2>Recomendaciones</h2><ol>')
    foreach ($x in $rec) { [void]$h.AppendLine(('<li>{0}</li>' -f (ConvertTo-HtmlSeguro $x))) }
    [void]$h.AppendLine('</ol>')
    foreach ($x in $Info.Avisos) { [void]$h.AppendLine(('<p class="nota">AVISO: {0}</p>' -f (ConvertTo-HtmlSeguro $x))) }
    [void]$h.AppendLine('<p class="nota">Generado por TITAN BLACKBOX en WinPE. El disco de origen se mantuvo en solo lectura.</p></main></body></html>')
    [System.IO.File]::WriteAllText((Join-Path $Dirs.Reporte 'reporte.html'), $h.ToString(), $script:Utf8ConBom)
    return [pscustomobject]@{ Resumen = ('{0}: {1}' -f $nivel, $resumen); Color = $color; Cuenta = $cuenta }
}
