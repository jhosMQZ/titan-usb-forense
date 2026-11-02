#Requires -Version 5.1
<#
.SYNOPSIS
    TITAN BLACKBOX - Recuperación avanzada (modo 2 del menú de TITAN).

.DESCRIPTION
    Diagnostica por qué no se pueden extraer los datos y aplica la estrategia
    que más probabilidades tiene de recuperarlos, sin escribir nunca en el disco
    de origen (que queda en SOLO LECTURA):

      archivos     Extracción adaptativa: cola priorizada (documentos, fotos,
                   Escritorio/Descargas, bases de datos, proyectos...), copia por
                   bloques con mapa reanudable, reintentos limitados, rescate de
                   la parte legible de archivos dañados, verificación SHA-256.
      imagen       Imagen sector a sector del disco o de una partición, con mapa
                   compatible con GNU ddrescue; después se monta la imagen en
                   solo lectura y se extraen los archivos desde ella.
      firmas       Recuperación por firmas (JPEG, PNG, GIF, PDF, Office, ZIP,
                   SQLite, MP4/MOV) cuando el sistema de archivos no sirve.
      particiones  Busca particiones perdidas (solo lectura); la reconstrucción
                   se hace únicamente sobre una imagen (copia de trabajo).

    Todo trabajo es reanudable (Casos\<fecha>_BLACKBOX\Datos\diario.tsv + Mapas\).
#>
param(
    [Parameter(Mandatory = $true)][string]$RutaHerramientas,
    [Parameter(Mandatory = $true)][string]$RutaRespaldo,
    [string]$Huella = '',
    [string]$IntegridadInicial = 'NO VERIFICADA',
    # --- Solo para pruebas en un PC (nunca desde el menú de WinPE) ---
    [switch]$PermitirFueraDeWinPE,
    [string]$RutaMotor = '',
    [int]$Disco = -1,
    [switch]$Automatico,
    [ValidateSet('', 'archivos', 'imagen', 'firmas', 'particiones')][string]$Estrategia = '',
    [string]$Reanudar = '',
    [string[]]$CarpetasPrueba = @(),
    [string]$OrigenFirmas = '',
    [string]$ImagenParticion = '',
    [string]$RutaConfig = ''
)
$ErrorActionPreference = 'Stop'
$aqui = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
foreach ($n in @('Comun', 'Disco', 'Malware', 'Persistencia', 'Respaldo', 'Reporte', 'Blackbox')) { . (Join-Path $aqui ('Lib\' + $n + '.ps1')) }

if ($Automatico -and -not ($PermitirFueraDeWinPE -or $env:TITAN_MODO_PRUEBA -eq '1')) { throw '-Automatico solo se admite en pruebas.' }
if ($Automatico) {
    # Pruebas: se aceptan las opciones por defecto sin preguntar
    function Read-Host {
        param([Parameter(ValueFromRemainingArguments = $true)]$Resto)
        return ''
    }
    function Read-Confirmacion {
        param([string]$Pregunta, [string]$Palabra = 'SI')
        Write-Log ("(automático) {0}: {1}" -f $Pregunta, $Palabra) -SoloArchivo
        return $true
    }
}

$inicioTotal = Get-Date
$marca = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $Reanudar -and -not $Automatico) {
    # ¿Hay trabajos anteriores que se puedan reanudar?
    $previos = @(Get-ChildItem -LiteralPath (Join-Path $RutaRespaldo 'Casos') -Directory -Filter '*_BLACKBOX' -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'trabajo.json') } | Sort-Object Name -Descending | Select-Object -First 9)
    if ($previos.Count -gt 0) {
        Write-Host ''
        Write-Host 'Trabajos anteriores de BLACKBOX (se pueden reanudar sin repetir lo ya verificado):' -ForegroundColor Cyan
        for ($i = 0; $i -lt $previos.Count; $i++) { Write-Host ('  [{0}] {1}' -f ($i + 1), $previos[$i].Name) }
        $rr = ([string](Read-Host 'Número para REANUDAR (Enter = trabajo nuevo)')).Trim()
        $nn = 0
        if ([int]::TryParse($rr, [ref]$nn) -and $nn -ge 1 -and $nn -le $previos.Count) { $Reanudar = $previos[$nn - 1].FullName }
    }
}
if ($Reanudar) {
    if (-not (Test-Path -LiteralPath (Join-Path $Reanudar 'trabajo.json'))) { throw "No es un trabajo de BLACKBOX: $Reanudar" }
    $caso = $Reanudar.TrimEnd('\')
} else {
    $caso = Join-Path $RutaRespaldo ("Casos\{0}_BLACKBOX" -f $marca)
}
# Antes de escribir NADA (carpeta del trabajo, registros): el destino no puede estar en el disco de origen
if ($Disco -ge 0) {
    $discoDestino = Get-NumeroDiscoDeVolumenDp -Letra $RutaRespaldo
    if ($discoDestino -lt 0) { Write-Host ('No se pudo saber a qué disco pertenece el destino {0}. No se escribió nada.' -f $RutaRespaldo) -ForegroundColor Red; exit 4 }
    if ($discoDestino -eq $Disco) {
        Write-Host ('Protección: el disco #{0} contiene el destino del respaldo ({1}). El destino nunca puede estar en el disco de origen. No se escribió nada.' -f $Disco, $RutaRespaldo) -ForegroundColor Red
        exit 4
    }
}
$Dirs = New-TrabajoBlackbox -Caso $caso -Identidad $null
$Ctx = @{
    RutaHerramientas = $RutaHerramientas; RutaRespaldo = $RutaRespaldo; Config = $null; Modo = 'BLACKBOX'
    Dirs = $Dirs; DiscoUsb = -1; DiscoObjetivo = -1; DiscoInfo = $null
    Volumenes = @(); VolWindows = $null; Sistema = $null; Perfiles = @(); Carpetas = @()
}
Initialize-Registro -ArchivoLog (Join-Path $Dirs.Registros ("principal_{0}.log" -f $marca))
try { Start-Transcript -Path (Join-Path $Dirs.Registros ("consola_{0}.txt" -f $marca)) -Force | Out-Null } catch { }
Initialize-RutasLargas
Disable-EdicionRapida

$archConfig = Join-Path $aqui 'config.json'
if ($RutaConfig) {
    if (-not $PermitirFueraDeWinPE) { throw '-RutaConfig solo se admite en pruebas.' }
    $archConfig = $RutaConfig
}
$Ctx.Config = Get-Content -LiteralPath $archConfig -Raw -Encoding UTF8 | ConvertFrom-Json
$cfg = $Ctx.Config.Blackbox
if (-not $cfg) { throw 'config.json no tiene la sección "Blackbox".' }
foreach ($r in @(@('Reintentos', 0, 20), @('EsperaMs', 0, 60000), @('BloqueKB', 4, 65536), @('MinimoKB', 1, 1024), @('MaxIntentosPorArchivo', 1, 10), @('UmbralArchivosConFalloFisico', 1, 1000), @('MaxErroresFisicosPorArchivo', 1, 100000), @('MargenLibreMB', 0, 65536))) {
    $v = 0
    if (-not [int]::TryParse([string]$cfg.($r[0]), [ref]$v) -or $v -lt $r[1] -or $v -gt $r[2]) { throw ('config.json Blackbox.{0} debe estar entre {1} y {2}' -f $r[0], $r[1], $r[2]) }
}
if (([int]$cfg.BloqueKB % 4) -ne 0) { throw 'Blackbox.BloqueKB debe ser múltiplo de 4.' }

$info = [ordered]@{
    Salud = $null; SaludMotor = $null; Diagnostico = @(); Seguridad = $null; Cola = @(); ResumenCola = $null
    Imagen = $null; Particiones = $null; Firmas = $null; Estrategias = [System.Collections.Generic.List[string]]::new()
    Herramientas = [System.Collections.Generic.List[string]]::new(); Avisos = [System.Collections.Generic.List[string]]::new()
    ClamAV = 'no ejecutado'; Abortado = $null; ModoFallo = $false; SecureBoot = 'NO EVALUADO'; Reanudado = [bool]$Reanudar
}

function Start-Fase {
    param([string]$Nombre)
    Write-Log $Nombre -Nivel FASE
}

Write-Host ''
Write-Host 'TITAN BLACKBOX - RECUPERACIÓN AVANZADA' -ForegroundColor Cyan
Write-Host 'Reglas: disco de origen en SOLO LECTURA - nada del equipo se ejecuta - nada se borra.' -ForegroundColor Cyan
Write-Host ("Carpeta del trabajo: {0}" -f $caso) -ForegroundColor Gray

$abortado = $false
try {
    # =======================================================================
    Start-Fase 'B0 - Comprobaciones previas'
    $esWinPE = Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT'
    if (-not $esWinPE -and -not $PermitirFueraDeWinPE) { throw 'BLACKBOX se ejecuta en WinPE, arrancando desde TITAN.' }
    $vm = Initialize-MotorRescate -RutaHerramientas $RutaHerramientas -RutaExplicita $RutaMotor -SinAncla:(-not $esWinPE)
    $info.Herramientas.Add($vm)
    $info.Herramientas.Add(('Windows PowerShell {0} sobre {1}' -f $PSVersionTable.PSVersion, [Environment]::OSVersion.VersionString))
    $info.Herramientas.Add('diskpart (Windows) para discos, solo lectura y letras')
    Write-Log ("Motor: {0}" -f $vm) -Nivel OK
    $Ctx.DiscoUsb = Get-NumeroDiscoDeLetra $RutaRespaldo
    $firmaEsperada = $null
    $idEsp = Get-FirmaDiscoUsbEsperada
    if ($null -ne $idEsp) { $firmaEsperada = '{0:X8}' -f $idEsp }
    elseif ($esWinPE) { throw 'Falta X:\Ancla\usb-id.txt.' }
    $info.SecureBoot = Get-EstadoSecureBoot
    Write-Log ("USB de trabajo: disco #{0} | Secure Boot: {1} | libre: {2}" -f $Ctx.DiscoUsb, $info.SecureBoot, (Format-Bytes ([double](Get-EspacioLibre $RutaRespaldo))))

    # =======================================================================
    Start-Fase 'B1 - Disco de origen, seguridad y volúmenes'
    $discos = Show-Discos -NumeroUsb $Ctx.DiscoUsb
    $candidatos = @($discos | Where-Object { $_.Number -ne $Ctx.DiscoUsb })
    if ($candidatos.Count -eq 0) { throw 'No se ve ningún disco además de TITAN. Si la BIOS sí lo muestra, puede faltar el controlador (Intel VMD/RST): vea la guía.' }
    $numero = $candidatos[0].Number
    if ($Disco -ge 0) { $numero = $Disco }
    elseif ($candidatos.Count -gt 1) {
        while ($true) {
            $rr = [string](Read-Host ('Número del disco a recuperar [{0}]' -f $numero))
            if ($rr.Trim() -eq '') { break }
            $nn = 0
            if ([int]::TryParse($rr, [ref]$nn) -and @($candidatos | ForEach-Object { $_.Number }) -contains $nn) { $numero = $nn; break }
            Write-Host 'Número no válido.' -ForegroundColor Yellow
        }
    }
    if ($numero -eq $Ctx.DiscoUsb) { throw ('Protección: el disco #{0} contiene el destino del respaldo ({1}). El destino nunca puede estar en el disco de origen.' -f $numero, $RutaRespaldo) }
    $Ctx.DiscoObjetivo = $numero
    $Ctx.DiscoInfo = Get-DetalleDiscoConTamanoDp -Numero $numero
    $previo = $null
    if ($Reanudar) {
        $previo = Get-Content -LiteralPath (Join-Path $caso 'trabajo.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$previo.Disco.Id -ne [string]$Ctx.DiscoInfo.Id -or [string]$previo.Disco.Modelo -ne [string]$Ctx.DiscoInfo.FriendlyName) {
            throw ('Este trabajo pertenece a otro disco ({0}, id {1}); el elegido es {2}, id {3}. No se reanuda.' -f $previo.Disco.Modelo, $previo.Disco.Id, $Ctx.DiscoInfo.FriendlyName, $Ctx.DiscoInfo.Id)
        }
        Write-Log 'Reanudando: el disco coincide con el del trabajo original.' -Nivel OK
    }
    $info.Seguridad = Test-SeguridadOperacion -DiscoOrigen $numero -DiscoUsb $Ctx.DiscoUsb -Destino $RutaRespaldo -FirmaUsbEsperada $firmaEsperada
    Write-Host ''
    Write-Host 'RESUMEN PARA CONFIRMAR' -ForegroundColor Cyan
    Write-Host ('  Disco a recuperar : #{0} {1} ({2}), id {3}' -f $numero, $Ctx.DiscoInfo.FriendlyName, (Format-Bytes ([double]$Ctx.DiscoInfo.Size)), $Ctx.DiscoInfo.Id)
    Write-Host '  Se pondrá en      : SOLO LECTURA (no se escribirá nada en él)'
    Write-Host ('  Destino           : {0} (disco #{1})' -f $RutaRespaldo, $Ctx.DiscoUsb)
    if (-not (Read-Confirmacion 'Confirme que el disco y el destino son correctos')) { throw 'Cancelado por el usuario.' }
    [void](Set-DiscoSoloLectura -Numero $numero -NumeroUsb $Ctx.DiscoUsb)
    $info.Seguridad = Test-SeguridadOperacion -DiscoOrigen $numero -DiscoUsb $Ctx.DiscoUsb -Destino $RutaRespaldo -FirmaUsbEsperada $firmaEsperada -ExigirSoloLectura
    Write-Log ("Disco #{0} en SOLO LECTURA: verificado." -f $numero) -Nivel OK
    $info.Diagnostico = @(Get-DiagnosticoVolumenes -Numero $numero)
    $bloqueados = @($info.Diagnostico | Where-Object { $_.Estado -eq 'VOLUMEN_BLOQUEADO' } | ForEach-Object { $_.Letra })
    if ($bloqueados.Count -gt 0) {
        # Solo la clave de recuperación legítima; la clave no se guarda en ningún registro
        Invoke-DesbloqueoBitLocker -Letras $bloqueados
        $info.Diagnostico = @(Get-DiagnosticoVolumenes -Numero $numero)
    }
    Write-Host ''
    Write-Host 'Volúmenes del disco:' -ForegroundColor Cyan
    foreach ($v in $info.Diagnostico) { Write-Host ('  Vol {0,-3} {1,-3} {2,-6} {3,10}  {4,-22} BitLocker: {5}' -f $v.Num, $v.Letra, $v.Fs, (Format-Bytes ([double]$v.Tamano)), $v.Estado, $v.BitLocker) }
    $legibles = @($info.Diagnostico | Where-Object { $_.Estado -eq 'LEGIBLE' } | ForEach-Object { $_.Letra })
    $Ctx.Volumenes = $legibles
    foreach ($v in $info.Diagnostico) {
        if ($v.Estado -eq 'VOLUMEN_BLOQUEADO') { $info.Estrategias.Add('VOLUMEN_BLOQUEADO'); Add-RegistroError -Fase 'Volúmenes' -Ruta $v.Letra -Mensaje 'VOLUMEN_BLOQUEADO: BitLocker sin desbloquear (falta la clave de recuperación)' }
        if ($v.Estado -eq 'VOLUMEN_NO_RECONOCIDO') { $info.Estrategias.Add('VOLUMEN_NO_RECONOCIDO'); Add-RegistroError -Fase 'Volúmenes' -Ruta $v.Letra -Mensaje 'VOLUMEN_NO_RECONOCIDO: Windows no reconoce su sistema de archivos' }
    }

    # Windows, perfiles y carpetas (lo mismo que el rescate seguro)
    $conWindows = @($legibles | Where-Object { [System.IO.File]::Exists("$_\Windows\System32\config\SYSTEM") })
    if ($conWindows.Count -ge 1) {
        $Ctx.VolWindows = $conWindows[0]
        $vw = $Ctx.VolWindows
        try {
            Mount-HiveOffline -Origen "$vw\Windows\System32\config\SOFTWARE" -Nombre 'OFF_SOFTWARE' -CarpetaTrabajo $Dirs.Trabajo
            Mount-HiveOffline -Origen "$vw\Windows\System32\config\SYSTEM" -Nombre 'OFF_SYSTEM' -CarpetaTrabajo $Dirs.Trabajo
            $Ctx.Sistema = Get-InfoSistemaOffline -VolWindows $vw
        } catch { Add-RegistroError -Fase 'Detección' -Ruta $vw -Mensaje ('Registro del sistema ilegible: ' + $_.Exception.Message) }
        $perfiles = @(Get-PerfilesOffline -VolWindows $vw)
        $k = 1
        foreach ($pf in $perfiles) {
            try { Mount-HiveOffline -Origen $pf.NtUser -Nombre ("OFF_NTUSER_{0}" -f $k) -CarpetaTrabajo $Dirs.Trabajo; $pf.Hive = 'OFF_NTUSER_{0}' -f $k } catch { }
            $k++
        }
        $Ctx.Perfiles = $perfiles
    }
    if (-not $Ctx.Sistema) { $Ctx.Sistema = [pscustomobject]@{ Nombre = '(no detectado)'; Producto = ''; Version = ''; Build = ''; LetraOriginal = 'C'; ControlSet = 'ControlSet001'; SystemRoot = '' } }

    # =======================================================================
    Start-Fase 'B2 - Diagnóstico del disco'
    $info.Salud = Get-SaludDisco -Numero $numero -RutaHerramientas $RutaHerramientas -CarpetaRegistros $Dirs.Registros
    $sm = Invoke-Motor -Argumentos @('salud', '--disco', [string]$numero)
    $info.SaludMotor = $sm
    $veredicto = [string]$info.Salud.Veredicto
    if ($sm.estado -eq 'OK' -and $sm.veredicto -and $sm.veredicto -ne 'DESCONOCIDO') {
        $veredicto = [string]$sm.veredicto
        $info.Herramientas.Add(('Salud del disco: {0} (motor TitanRescate)' -f $sm.fuente))
    }
    Write-Log ("Salud del disco: {0}" -f $veredicto)
    if ($sm.PSObject.Properties['desgastePct']) { Write-Log ("NVMe: desgaste {0}%, reserva {1}%, errores de integridad {2}, horas {3}, temperatura {4} °C" -f $sm.desgastePct, $sm.reservaDisponiblePct, $sm.erroresIntegridadMedio, $sm.horasEncendido, $sm.temperaturaC) }
    $info.ModoFallo = (@('MALO', 'DUDOSO') -contains $veredicto)
    if ($veredicto -eq 'DESCONOCIDO') {
        Write-Host 'No se pudo leer la salud del disco. Si el equipo se colgaba, hacía ruidos o tardaba mucho, conviene el modo de fallo.' -ForegroundColor Yellow
        $op = Read-Opcion -Pregunta '¿Tratar el disco como posiblemente dañado? (S = sí, recomendado / N = no) [S]' -Opciones @('S', 'N') -PorDefecto 'S'
        $info.ModoFallo = ($op -eq 'S')
    }
    if ($info.ModoFallo) { Write-Log 'Modo de fallo: primero se rescata lo legible de todo (pasada rápida), después se insiste en lo parcial.' -Nivel AVISO }

    # =======================================================================
    Start-Fase 'B3 - Estrategia'
    $recomendada = 'archivos'
    if ($legibles.Count -eq 0) { $recomendada = 'particiones' }
    if (-not $Estrategia) {
        if ($Automatico) { $Estrategia = $recomendada }
        else {
            Write-Host ''
            Write-Host 'Estrategias disponibles:' -ForegroundColor Cyan
            Write-Host '  A = Extracción adaptativa de archivos (recomendada si hay volúmenes legibles)'
            Write-Host '  I = Imagen sector a sector del disco o de una partición (luego se extrae desde la imagen)'
            Write-Host '  F = Recuperación por firmas (archivos borrados o volumen ilegible; se pierden los nombres)'
            Write-Host '  P = Buscar particiones perdidas (solo lectura)'
            $def = @{ archivos = 'A'; particiones = 'P' }[$recomendada]
            $op = Read-Opcion -Pregunta ('Estrategia [{0}]' -f $def) -Opciones @('A', 'I', 'F', 'P') -PorDefecto $def
            $Estrategia = @{ A = 'archivos'; I = 'imagen'; F = 'firmas'; P = 'particiones' }[$op]
        }
    }
    Write-Log ("Estrategia elegida: {0} (recomendada: {1})" -f $Estrategia, $recomendada)

    $identidad = [ordered]@{
        Version = 1; Creado = (Get-Date -Format 's'); Estrategia = $Estrategia
        Disco = [ordered]@{ Numero = $numero; Modelo = $Ctx.DiscoInfo.FriendlyName; Id = $Ctx.DiscoInfo.Id; Tamano = $Ctx.DiscoInfo.Size; Bus = $Ctx.DiscoInfo.BusType }
        Volumenes = @($info.Diagnostico | ForEach-Object { [ordered]@{ Letra = $_.Letra; Serie = $_.Serie; Fs = $_.Fs; Tamano = $_.Tamano; Estado = $_.Estado } })
    }
    if (-not $Reanudar) { [System.IO.File]::WriteAllText((Join-Path $caso 'trabajo.json'), ($identidad | ConvertTo-Json -Depth 5), $script:Utf8ConBom) }

    # =======================================================================
    Start-Fase ('B4 - Ejecución: ' + $Estrategia)
    $origenArchivos = $null   # volúmenes de los que se extraen archivos (disco o imagen montada)
    $vhdMontado = $null

    if ($Estrategia -eq 'imagen') {
        $tabla = Invoke-Motor -Argumentos @('particiones', '--origen', ('\\.\PhysicalDrive{0}' -f $numero), '--solo-tabla')
        $opciones = [System.Collections.Generic.List[object]]::new()
        $infoDisco = Invoke-Motor -Argumentos @('info', '--origen', ('\\.\PhysicalDrive{0}' -f $numero))
        if ($infoDisco.estado -ne 'OK') { throw ('No se pudo leer el tamaño exacto del disco: ' + $infoDisco.mensaje) }
        $opciones.Add([pscustomobject]@{ Nombre = 'Disco completo'; Inicio = [int64]0; Bytes = [int64]$infoDisco.longitud })
        foreach ($p in @($tabla.tabla)) { $opciones.Add([pscustomobject]@{ Nombre = ('Partición en {0} ({1})' -f (Format-Bytes ([double]$p.inicioBytes)), $p.tipo); Inicio = [int64]$p.inicioBytes; Bytes = [int64]$p.bytes }) }
        for ($i = 0; $i -lt $opciones.Count; $i++) { Write-Host ('  [{0}] {1} - {2}' -f ($i + 1), $opciones[$i].Nombre, (Format-Bytes ([double]$opciones[$i].Bytes))) }
        $sel = 1
        $cabe = @()
        $libre = Get-EspacioLibre $RutaRespaldo
        for ($i = 0; $i -lt $opciones.Count; $i++) { if ($opciones[$i].Bytes + [int64]$cfg.MargenLibreMB * 1MB -le $libre) { $cabe += ($i + 1) } }
        if ($Automatico -and $cabe.Count -gt 0) { $sel = $cabe[0] }
        elseif (-not $Automatico) {
            $rr = ([string](Read-Host 'Número a copiar como imagen')).Trim()
            $nn = 0; if ([int]::TryParse($rr, [ref]$nn) -and $nn -ge 1 -and $nn -le $opciones.Count) { $sel = $nn }
        }
        $obj = $opciones[$sel - 1]
        $necesario = $obj.Bytes + [int64]$cfg.MargenLibreMB * 1MB
        # Destino de la imagen: TITAN o un disco EXTERNO (nunca el de origen)
        $destImg = $RutaRespaldo
        $dirImg = $Dirs.Imagenes
        if (-not $Automatico) {
            Write-Host ('Espacio libre en TITAN: {0}. La imagen necesita {1}.' -f (Format-Bytes ([double]$libre)), (Format-Bytes ([double]$necesario)))
            $rr = ([string](Read-Host 'Destino de la imagen: Enter = TITAN, o la LETRA de un disco externo (p. ej. F)')).Trim().TrimEnd(':', '\')
            if ($rr -match '^[A-Za-z]$') {
                $destImg = $rr.ToUpperInvariant() + ':\'
                $dirImg = Join-Path $destImg ('TITAN_IMAGENES\' + (Split-Path -Path $caso -Leaf))
            }
        }
        $info.Seguridad = Test-SeguridadOperacion -DiscoOrigen $numero -DiscoUsb $Ctx.DiscoUsb -Destino $destImg -FirmaUsbEsperada $firmaEsperada -ExigirSoloLectura -EspacioMinimo $necesario
        New-Item -ItemType Directory -Path $dirImg -Force | Out-Null
        $img = Join-Path $dirImg ('disco{0}_{1}.img' -f $numero, $obj.Inicio)
        $mapa = $img + '.map'
        $arg = @('imagen', '--origen', ('\\.\PhysicalDrive{0}' -f $numero), '--destino', $img, '--mapa', $mapa)
        if ($obj.Inicio -gt 0) { $arg += @('--inicio', [string]$obj.Inicio, '--longitud', [string]$obj.Bytes) }
        $arg += @('--bloque', [string]([int]$cfg.BloqueKB * 1024), '--reintentos', [string][int]$cfg.Reintentos, '--espera-ms', [string][int]$cfg.EsperaMs, '--max-errores', [string][int]$cfg.MaxErroresFisicosPorArchivo)
        if ($info.ModoFallo) { $arg += @('--fase', 'rapida') }
        Write-Log ("Imagen: {0} -> {1} ({2})" -f $obj.Nombre, $img, (Format-Bytes ([double]$obj.Bytes)))
        $ri = Invoke-Motor -Argumentos $arg -Progreso
        if ($info.ModoFallo -and $ri.estado -eq 'RECUPERADO_PARCIAL') {
            Write-Log 'Segunda pasada de la imagen sobre las zonas fallidas (raspado y reintentos).' -Nivel AVISO
            $arg = $arg | Where-Object { $_ -ne '--fase' -and $_ -ne 'rapida' }
            $ri = Invoke-Motor -Argumentos $arg -Progreso
        }
        $info.Imagen = [pscustomobject]@{ Objeto = $obj.Nombre; Archivo = $img; Mapa = $mapa; Resultado = $ri; Completa = ($ri.bytesMalos -eq 0 -and $ri.bytesPendientes -eq 0 -and $ri.estado -like 'RECUPERADO*') }
        $info.Estrategias.Add(('Imagen sector a sector con mapa reanudable (formato ddrescue): {0}' -f $ri.estado))
        Write-Log ("Imagen: {0} | leídos {1} | ilegibles {2}" -f $ri.estado, (Format-Bytes ([double]$ri.bytesOk)), (Format-Bytes ([double]$ri.bytesMalos))) -Nivel OK
        if ($ri.estado -like 'RECUPERADO*') {
            # Trabajar sobre la imagen: se monta como VHD en solo lectura (disco completo o partición)
            $vhd = [System.IO.Path]::ChangeExtension($img, '.vhd')
            # La copia recibe una identidad de disco nueva: así se puede montar junto al original
            $rn = Invoke-Motor -Argumentos @('nueva-firma', '--imagen', $img)
            Write-Log ("Identidad nueva de la copia: {0} {1}" -f $rn.estado, $rn.cambios) -SoloArchivo
            $rv = Invoke-Motor -Argumentos @('vhd', '--imagen', $img, '--salida', $vhd)
            if ($rv.estado -eq 'OK') {
                $info.Imagen | Add-Member -NotePropertyName Vhd -NotePropertyValue $vhd -Force
                if ($obj.Inicio -eq 0) {
                    $mi = Mount-ImagenSoloLectura -Vhd $vhd
                    $vhdMontado = $vhd
                    $info.Imagen | Add-Member -NotePropertyName Montaje -NotePropertyValue $mi -Force
                    $origenArchivos = @($mi.Letras)
                    Write-Log ("Imagen montada en solo lectura (disco #{0}, letras {1}); se extraen los archivos desde la imagen." -f $mi.Disco, ($mi.Letras -join ', ')) -Nivel OK
                } else {
                    $info.Avisos.Add('La imagen es de una sola partición (sin tabla): para montarla, use la estrategia de particiones sobre la imagen o un programa que lea imágenes de volumen.')
                }
            } else { $info.Avisos.Add('No se pudo crear el VHD de la imagen: ' + $rv.mensaje) }
        }
    }

    if ($Estrategia -eq 'particiones') {
        $src = ('\\.\PhysicalDrive{0}' -f $numero)
        if ($ImagenParticion) { $src = $ImagenParticion }
        Write-Log ("Buscando particiones en {0} (solo lectura; puede tardar en discos grandes)..." -f $src)
        $rp = Invoke-Motor -Argumentos @('particiones', '--origen', $src) -Progreso
        $info.Particiones = $rp
        $perdidas = @($rp.halladas | Where-Object { -not $_.enTabla })
        Write-Log ("Tabla {0}: {1} particiones | sistemas de archivos hallados: {2} | fuera de la tabla: {3}" -f $rp.estilo, @($rp.tabla).Count, @($rp.halladas).Count, $perdidas.Count) -Nivel OK
        $info.Estrategias.Add(('Búsqueda de particiones (MBR/GPT + sectores de arranque NTFS/exFAT/FAT32): {0} perdidas' -f $perdidas.Count))
        if ($perdidas.Count -gt 0 -and $ImagenParticion) {
            # Reconstrucción experimental SOLO sobre la imagen (copia de trabajo)
            $spec = ($perdidas | Select-Object -First 4 | ForEach-Object { '{0}:{1}:{2}' -f $_.inicioBytes, $_.bytes, $(if ($_.fs -eq 'FAT32') { '0C' } else { '07' }) }) -join ','
            $rm = Invoke-Motor -Argumentos @('reconstruir-mbr', '--imagen', $ImagenParticion, '--particiones', $spec)
            $info.Particiones | Add-Member -NotePropertyName Reconstruccion -NotePropertyValue $rm -Force
            if ($rm.estado -eq 'OK') {
                $info.Estrategias.Add('MBR reconstruido en la COPIA de imagen (sector 0 original guardado en .sector0.bak)')
                $vhd = [System.IO.Path]::ChangeExtension($ImagenParticion, '.vhd')
                $rv = Invoke-Motor -Argumentos @('vhd', '--imagen', $ImagenParticion, '--salida', $vhd)
                if ($rv.estado -eq 'OK') {
                    $mi = Mount-ImagenSoloLectura -Vhd $vhd
                    $vhdMontado = $vhd
                    $origenArchivos = @($mi.Letras)
                    Write-Log ("Imagen reconstruida montada en solo lectura: {0}" -f ($mi.Letras -join ', ')) -Nivel OK
                }
            }
        } elseif ($perdidas.Count -gt 0) {
            $info.Avisos.Add('Hay particiones fuera de la tabla. Para recuperarlas sin tocar el disco: haga primero una IMAGEN (estrategia I) en un disco externo con espacio y repita la búsqueda sobre la imagen.')
        }
    }

    if ($Estrategia -eq 'firmas') {
        $src = $OrigenFirmas
        if (-not $src) {
            $opc = [System.Collections.Generic.List[object]]::new()
            foreach ($v in $info.Diagnostico) { if ($v.Letra -and $v.Estado -ne 'OCULTO_O_SISTEMA') { $opc.Add([pscustomobject]@{ Nombre = ('Volumen {0} ({1}, {2})' -f $v.Letra, $v.Fs, $v.Estado); Ruta = ('\\.\{0}' -f $v.Letra.TrimEnd('\')) }) } }
            $opc.Add([pscustomobject]@{ Nombre = ('Disco completo #{0}' -f $numero); Ruta = ('\\.\PhysicalDrive{0}' -f $numero) })
            for ($i = 0; $i -lt $opc.Count; $i++) { Write-Host ('  [{0}] {1}' -f ($i + 1), $opc[$i].Nombre) }
            $sel = 1
            if (-not $Automatico) { $rr = ([string](Read-Host 'Origen para la búsqueda por firmas [1]')).Trim(); $nn = 0; if ([int]::TryParse($rr, [ref]$nn) -and $nn -ge 1 -and $nn -le $opc.Count) { $sel = $nn } }
            $src = $opc[$sel - 1].Ruta
        }
        $info.Seguridad = Test-SeguridadOperacion -DiscoOrigen $numero -DiscoUsb $Ctx.DiscoUsb -Destino $RutaRespaldo -FirmaUsbEsperada $firmaEsperada -ExigirSoloLectura -EspacioMinimo 1GB
        Write-Log ("Recuperación por firmas en {0} (lee todo el área; los nombres y carpetas originales no se recuperan)" -f $src) -Nivel AVISO
        $rf = Invoke-Motor -Argumentos @('firmas', '--origen', $src, '--destino', $Dirs.Firmas, '--tipos', [string]$cfg.TiposFirmas, '--max-mb', '1024') -Progreso
        if ($rf.estado -ne 'OK') { throw ('La búsqueda por firmas no se pudo hacer ({0}): {1}' -f $rf.estado, $rf.mensaje) }
        Write-Log ('Firmas: {0} archivos hallados, {1} errores de lectura, {2} examinados.' -f $rf.hallados, $rf.erroresLectura, (Format-Bytes ([double]$rf.bytesEscaneados))) -Nivel OK
        $info.Firmas = $rf
        $info.Estrategias.Add(('Recuperación por firmas: {0} archivos ({1} errores de lectura)' -f $rf.hallados, $rf.erroresLectura))
        if ($rf.indice -and (Test-Path -LiteralPath $rf.indice)) {
            $lista = Get-Content -LiteralPath $rf.indice -Raw -Encoding UTF8 | ConvertFrom-Json
            Export-ListaCsv -Ruta (Join-Path $Dirs.Datos 'firmas.csv') -Objetos @($lista) -Columnas @('archivo', 'tipo', 'offset', 'tamano', 'estructuraCompleta', 'sha256')
        }
    }

    if ($Estrategia -eq 'archivos' -or $origenArchivos) {
        if ($origenArchivos) {
            # Desde la imagen montada: cada volumen legible de la imagen
            $Ctx.Carpetas = @()
            foreach ($l in $origenArchivos) {
                $usu = Join-Path $l 'Users'
                $raiz = $l + '\'
                if (Test-Path -LiteralPath $usu) { $raiz = $usu }
                $Ctx.Carpetas += [pscustomobject]@{ Etiqueta = ('Imagen_{0}' -f $l.Substring(0, 1)); Origen = $raiz.TrimEnd('\'); Prioridad = 1; Tipo = 'Imagen'; Destino = ''; Incluida = $true }
            }
        } elseif ($CarpetasPrueba.Count -gt 0) {
            $Ctx.Carpetas = @($CarpetasPrueba | ForEach-Object { [pscustomobject]@{ Etiqueta = (Split-Path -Path $_ -Leaf); Origen = $_.TrimEnd('\'); Prioridad = 1; Tipo = 'Usuario'; Destino = ''; Incluida = $true } })
        } else {
            if ($legibles.Count -eq 0) { throw 'No hay volúmenes legibles: use la estrategia de particiones o de firmas.' }
            if (@($Ctx.Perfiles).Count -gt 0) { $Ctx.Carpetas = @(Get-CarpetasRespaldo -Ctx $Ctx) }
            else {
                $Ctx.Carpetas = @($legibles | ForEach-Object { [pscustomobject]@{ Etiqueta = ('Volumen_{0}' -f $_.Substring(0, 1)); Origen = $_; Prioridad = 1; Tipo = 'Volumen'; Destino = ''; Incluida = $true } })
            }
        }
        $info.Estrategias.Add('Extracción adaptativa por archivo (cola priorizada, mapa reanudable, verificación SHA-256)')
        $cola = New-ColaRecuperacion -Ctx $Ctx -Config $cfg
        if ($Reanudar) {
            $rr = Restore-EstadoDesdeDiario -Cola $cola -RutaDiario $script:ArchivoDiario -Dirs $Dirs
            Write-Log ("Reanudación: {0} archivos con historial, {1} verificados por SHA-256, {2} se repiten." -f $rr.ConEntrada, $rr.Revisados, $rr.Reencolados) -Nivel OK
            $info.Estrategias.Add('Reanudación verificada por SHA-256 de las copias existentes')
        }
        # Gancho de PRUEBA: fallos simulados por archivo (solo TITAN_MODO_PRUEBA=1)
        if ($env:TITAN_MODO_PRUEBA -eq '1' -and $env:TITAN_PRUEBA_FALLOS) {
            foreach ($par in $env:TITAN_PRUEBA_FALLOS.Split(';')) {
                $p = $par.Split('|')
                foreach ($it in $cola) { if ($it.Relativa -like ('*' + $p[0])) { $it | Add-Member -NotePropertyName PruebaFallos -NotePropertyValue $p[1] -Force } }
            }
        }
        if ($env:TITAN_MODO_PRUEBA -eq '1' -and $env:TITAN_PRUEBA_CORTAR) {
            $p = $env:TITAN_PRUEBA_CORTAR.Split('|')
            foreach ($it in $cola) { if ($it.Relativa -like ('*' + $p[0])) { $it | Add-Member -NotePropertyName PruebaCortar -NotePropertyValue ([int64]$p[1]) -Force } }
        }
        $porPri = $cola | Group-Object -Property Categoria | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }
        $totalBytes = [int64]0; foreach ($it in $cola) { $totalBytes += $it.Tamano }
        Write-Log ("Cola: {0} archivos ({1}). Por prioridad: {2}" -f $cola.Count, (Format-Bytes ([double]$totalBytes)), ($porPri -join ' | '))
        if ($totalBytes -gt (Get-EspacioLibre $RutaRespaldo)) {
            Write-Log 'No cabe todo en el destino: se copian primero los archivos más importantes y el resto queda PENDIENTE.' -Nivel AVISO
        }
        $info.Cola = $cola
        $rc = Invoke-ColaRecuperacion -Cola $cola -Dirs $Dirs -Config $cfg -Destino $RutaRespaldo -ModoFallo:$info.ModoFallo
        foreach ($e in $rc.Estrategias) { $info.Estrategias.Add($e) }
        $info.Abortado = $rc.Abortado
        $info.ModoFallo = $rc.ModoFallo
    }

    # Antivirus sobre lo RECUPERADO (en la USB: no vuelve a leer el disco de origen)
    if ($cfg.EscanearRecuperadosConClamAV) {
        $objetivos = @($Dirs.Respaldo, $Dirs.Parciales, $Dirs.Firmas) | Where-Object { @(Get-ChildItem -LiteralPath $_ -Force -ErrorAction SilentlyContinue).Count -gt 0 }
        if (@($objetivos).Count -gt 0) {
            $ic = Get-InfoClamAV -RutaHerramientas $RutaHerramientas
            if ($ic.Disponible) {
                $info.Herramientas.Add([string]$ic.Version)
                $rcl = Invoke-EscaneoClamAV -Objetivos @($objetivos) -InfoClamAV $ic -Config $Ctx.Config -CarpetaRegistros $Dirs.Registros -CarpetaTemporal $Dirs.Tmp
                $info.ClamAV = ('{0:N0} archivos recuperados escaneados, {1} detecciones' -f $rcl.Escaneados, $rcl.Infectados)
                foreach ($k in @($script:Sospechosos.Keys)) {
                    $s = $script:Sospechosos[$k]
                    if (-not ($s.Motores -contains 'ClamAV')) { continue }
                    try {
                        $q = Join-Path $Dirs.Cuarentena ('AV_' + (Get-NombreSeguro ([System.IO.Path]::GetFileName($s.Ruta)) 40) + '.cuar')
                        [void](Protect-ArchivoCuarentena -Origen $s.Ruta -Destino $q)
                        [System.IO.File]::Delete((Get-RutaLarga $s.Ruta))
                        foreach ($it in $info.Cola) {
                            if ($it.Destino -and $it.Destino -ieq $s.Ruta) {
                                $it.Estado = 'OMITIDO_POR_SEGURIDAD'; $it.Motivo = ('ClamAV: ' + ($s.Firmas -join ', ')); $it.Destino = $q
                                Add-EntradaDiario -Item $it -Estado $it.Estado -Categoria 'SEGURIDAD' -Estrategia 'ClamAV sobre la copia' -R $null -Destino $q -Mensaje $it.Motivo
                            }
                        }
                        Write-Log ("Copia infectada retirada a cuarentena cifrada: {0}" -f $s.Ruta) -Nivel DET
                    } catch { Add-RegistroError -Fase 'Antivirus' -Ruta $s.Ruta -Mensaje $_.Exception.Message }
                }
            } else { $info.ClamAV = ('no disponible: ' + $ic.Motivo); $info.Avisos.Add('El antivirus no se ejecutó sobre lo recuperado: analícelo con Microsoft Defender en un PC sano antes de abrirlo.') }
        }
    }
    # Marca de la Web en las copias (después del hash; no altera el contenido)
    if ($Ctx.Config.MarcarOrigenInternet) {
        foreach ($it in $info.Cola) { if ($it.Estado -like 'RECUPERADO*' -and $it.Destino) { try { Set-MarcaInternet -Ruta $it.Destino } catch { } } }
    }
} catch {
    $abortado = $true
    Add-RegistroError -Fase 'General' -Ruta '' -Mensaje $_.Exception.Message
    Write-Log ("Proceso detenido: {0}" -f $_.Exception.Message) -Nivel ERROR
    Write-Log ("  en la línea {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, ([string]$_.InvocationInfo.Line).Trim()) -Nivel ERROR -SoloArchivo
} finally {
    try { Dismount-HivesOffline } catch { }
    if ($vhdMontado) { try { Dismount-Imagen -Vhd $vhdMontado } catch { } }
}

# ===========================================================================
Start-Fase 'B5 - Verificación e informe'
$integridadFinal = 'NO VERIFICADA (fuera de WinPE)'
if (Test-Path -LiteralPath 'X:\Ancla\Iniciar.ps1') {
    try {
        $rv = Invoke-Nativo 'powershell.exe' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'X:\Ancla\Iniciar.ps1', '-SoloVerificar', '-Herramientas', $RutaHerramientas) -ArchivoSalida (Join-Path $Dirs.Registros 'integridad_final.txt')
        if ($rv.Codigo -eq 0 -or $rv.Codigo -eq 2) { $integridadFinal = 'CORRECTA' } else { $integridadFinal = 'FALLIDA' }
    } catch { $integridadFinal = 'NO SE PUDO VERIFICAR' }
}
try {
    Export-ResultadosCsv -Cola $info.Cola -Ruta (Join-Path $Dirs.Datos 'resultado_archivos.csv')
    Export-ListaCsv -Ruta (Join-Path $Dirs.Datos 'errores.csv') -Objetos $script:Errores -Columnas @('Fecha', 'Fase', 'Ruta', 'Mensaje')
    $rep = New-ReporteBlackbox -Ctx $Ctx -Info $info -Dirs $Dirs -Inicio $inicioTotal -Abortado $abortado -Huella $Huella -IntegridadInicial $IntegridadInicial -IntegridadFinal $integridadFinal
    Write-Log ("Informe: {0}" -f (Join-Path $Dirs.Reporte 'reporte.html')) -Nivel OK
    Write-Host ''
    Write-Host $rep.Resumen -ForegroundColor $rep.Color
} catch {
    Write-Log ("No se pudo generar el informe: {0}" -f $_.Exception.Message) -Nivel ERROR
    Write-Log ("  en la línea {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, ([string]$_.InvocationInfo.Line).Trim()) -Nivel ERROR -SoloArchivo
}
try { if (Test-Path -LiteralPath $Dirs.Tmp) { Remove-Item -LiteralPath $Dirs.Tmp -Recurse -Force } } catch { }
try { Stop-Transcript | Out-Null } catch { }
Write-Host ''
Write-Host ("Trabajo guardado en: {0}" -f $caso) -ForegroundColor Cyan
Write-Host 'Es reanudable: elija otra vez la recuperación avanzada y "Reanudar".' -ForegroundColor Cyan
if ($abortado) { exit 1 } else { exit 0 }
