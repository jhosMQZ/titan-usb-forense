<#
.SYNOPSIS
    Analiza un PC con Windows 11 que no arranca, desde WinPE, y respalda los
    archivos limpios al USB.

.DESCRIPTION
    Flujo (cada fase queda registrada en Registros\principal.log):
      1. Detectar discos/unidades, confirmar y montar el disco en SOLO LECTURA.
      2. Revisar el disco: chkdsk SIN reparar + salud SMART.
      3. Escaneo antivirus sin conexión (ClamAV) de todo el disco, incluidos
         ocultos y comprimidos; importa detecciones de Defender si existen.
      4. Revisar persistencia (Inicio, Run, tareas, servicios, controladores).
      5. Inventario SHA-256 de todos los archivos (CSV) + heurísticas.
      6. Cuarentena cifrada de lo sospechoso y copia con robocopy (/COPY:DAT).
      7. Verificación de hashes origen vs destino.
      8. Reporte HTML/TXT con recomendaciones.

    Reglas de seguridad que el script garantiza:
      - El disco analizado se pone en SOLO LECTURA antes de leer nada.
      - Nunca se ejecuta ningún archivo del equipo analizado.
      - Nunca se borra nada del equipo analizado. Lo sospechoso se COPIA
        CIFRADO a Cuarentena con el motivo registrado.

.NOTES
    Lo lanza X:\Ancla\Iniciar.ps1 tras verificar la integridad del USB.
    Requiere WinPE con: WinPE-WMI, WinPE-NetFX, WinPE-Scripting,
    WinPE-PowerShell, WinPE-StorageWMI y WinPE-SecureStartup.
#>
param(
    [Parameter(Mandatory = $true)][string]$RutaHerramientas,
    [Parameter(Mandatory = $true)][string]$RutaRespaldo,
    [string]$Huella = '(no informada)',
    [string]$IntegridadInicial = 'NO VERIFICADA',
    [switch]$PermitirFueraDeWinPE
)

$ErrorActionPreference = 'Stop'
$RutaHerramientas = $RutaHerramientas.Substring(0, 2) + '\'
$RutaRespaldo = $RutaRespaldo.Substring(0, 2) + '\'

. (Join-Path $PSScriptRoot 'Lib\Comun.ps1')
. (Join-Path $PSScriptRoot 'Lib\Disco.ps1')
. (Join-Path $PSScriptRoot 'Lib\Malware.ps1')
. (Join-Path $PSScriptRoot 'Lib\Persistencia.ps1')
. (Join-Path $PSScriptRoot 'Lib\Respaldo.ps1')
. (Join-Path $PSScriptRoot 'Lib\Reporte.ps1')

# ---------------------------------------------------------------------------
# Preparación de la carpeta del caso
# ---------------------------------------------------------------------------
$inicioTotal = Get-Date
$marca = Get-Date -Format 'yyyyMMdd_HHmmss'
$caso = Join-Path $RutaRespaldo ("Casos\$marca")
$Ctx = @{
    RutaHerramientas = $RutaHerramientas
    RutaRespaldo     = $RutaRespaldo
    Config           = $null
    Modo             = 'Normal'
    Dirs             = @{
        Caso = $caso; Respaldo = "$caso\Respaldo"; Cuarentena = "$caso\Cuarentena"; Registros = "$caso\Registros"
        Datos = "$caso\Datos"; Reporte = "$caso\Reporte"; Trabajo = "$caso\Trabajo"; Tmp = "$caso\Trabajo\tmp"
    }
    DiscoUsb = -1; DiscoObjetivo = -1; DiscoInfo = $null
    Volumenes = @(); VolWindows = $null; Sistema = $null
    Perfiles = @(); Carpetas = @()
    Tiempos = [ordered]@{}
}
foreach ($d in $Ctx.Dirs.Values) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
Initialize-Registro -ArchivoLog (Join-Path $Ctx.Dirs.Registros 'principal.log')
try { Start-Transcript -Path (Join-Path $Ctx.Dirs.Registros 'consola.txt') -Force | Out-Null } catch { }
Initialize-RutasLargas
Disable-EdicionRapida

$cfgRuta = Join-Path $PSScriptRoot 'config.json'
$Ctx.Config = Get-Content -LiteralPath $cfgRuta -Raw -Encoding UTF8 | ConvertFrom-Json

function Test-Configuracion {
    # Rechaza valores fuera de rango o con formato peligroso en config.json
    param($C)
    $err = @()
    $rangos = @(
        @('CuarentenaMaxMB', 1, 4096), @('RobocopyHilos', 1, 32), @('RobocopyReintentos', 0, 10),
        @('RobocopyEspera', 0, 60), @('MargenLibreMB', 0, 65536), @('DiasMaxAntiguedadFirmas', 1, 90)
    )
    foreach ($r in $rangos) {
        $v = 0
        if (-not [int]::TryParse([string]$C.($r[0]), [ref]$v) -or $v -lt $r[1] -or $v -gt $r[2]) { $err += ('{0} debe estar entre {1} y {2}' -f $r[0], $r[1], $r[2]) }
    }
    foreach ($r in @(@('MaxFileSizeMB', 1, 2000), @('MaxScanSizeMB', 1, 4000), @('MaxFiles', 1, 1000000), @('MaxRecursion', 1, 64))) {
        $v = 0
        if (-not [int]::TryParse([string]$C.ClamAV.($r[0]), [ref]$v) -or $v -lt $r[1] -or $v -gt $r[2]) { $err += ('ClamAV.{0} debe estar entre {1} y {2}' -f $r[0], $r[1], $r[2]) }
    }
    if (@('TodoElDisco', 'SoloRespaldo') -notcontains [string]$C.HashAlcance) { $err += 'HashAlcance debe ser TodoElDisco o SoloRespaldo' }
    foreach ($x in @($C.ExcluirCarpetasEnRespaldo)) {
        if ([string]$x -notmatch '^[^\\/:*?"<>|]+$' -or [string]$x -match '^\.+$') { $err += "Nombre de carpeta excluida no válido: $x" }
    }
    foreach ($x in @($C.CarpetasProyectosCandidatas)) {
        if ([string]$x -notmatch '^%(USERPROFILE|SYSTEMDRIVE)%\\' -or [string]$x -match '\.\.') { $err += "Carpeta candidata no válida (debe empezar por %USERPROFILE%\ o %SYSTEMDRIVE%\ y sin '..'): $x" }
    }
    if ($err.Count -gt 0) { throw ('config.json no válido: ' + ($err -join '; ')) }
}
Test-Configuracion -C $Ctx.Config

# Limpieza de temporales de ejecuciones anteriores interrumpidas (copias de
# hives y archivos extraídos por ClamAV: pueden contener datos sensibles o
# malware sin cifrar). Son archivos NUESTROS en el USB.
foreach ($t in @(Get-ChildItem -LiteralPath (Join-Path $RutaRespaldo 'Casos') -Directory -ErrorAction SilentlyContinue)) {
    $tw = Join-Path $t.FullName 'Trabajo'
    if ($t.FullName -ne $caso -and (Test-Path -LiteralPath $tw)) {
        try { Remove-Item -LiteralPath $tw -Recurse -Force -ErrorAction Stop; Write-Log ("Temporales antiguos eliminados: {0}" -f $tw) -SoloArchivo } catch { }
    }
}

# Resultados que alimentan el reporte
$resClam = $null; $infoClam = $null; $externas = 0; $chk = @(); $salud = $null
$persist = @(); $inv = $null; $filasCuar = @(); $verif = $null
$antivirusEjecutado = $false; $firmasAntiguas = $false; $soloLectura = $false
$integridadFinal = 'NO VERIFICADA'
$secureBoot = 'NO EVALUADO'

function Start-Fase {
    param([string]$Nombre)
    $script:faseNombre = $Nombre
    $script:faseInicio = Get-Date
    Write-Log $Nombre -Nivel FASE
}
function Stop-Fase {
    $dur = Format-Duracion ((Get-Date) - $script:faseInicio)
    $Ctx.Tiempos[$script:faseNombre] = $dur
    Write-Log ('Duración: {0}' -f $dur) -SoloArchivo
}

Write-Host ''
Write-Host 'ANALIZADOR DE EQUIPO SIN CONEXIÓN' -ForegroundColor Cyan
Write-Host 'Reglas: disco en SOLO LECTURA - nada del equipo se ejecuta - nada se borra.' -ForegroundColor Cyan
Write-Host ("Carpeta del caso: {0}" -f $caso) -ForegroundColor Gray

$abortado = $false
try {
    # =======================================================================
    # FASE 0 - Comprobaciones previas
    # =======================================================================
    Start-Fase 'FASE 0 - Comprobaciones previas'
    $esWinPE = Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT'
    if (-not $esWinPE -and -not $PermitirFueraDeWinPE) {
        throw 'Este script debe ejecutarse en WinPE (arrancando desde el USB). Usar -PermitirFueraDeWinPE solo para pruebas.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\diskpart.exe'))) {
        throw 'No se encontró diskpart.exe en WinPE.'
    }
    Write-Log ("PowerShell {0} | rutas largas: {1}" -f $PSVersionTable.PSVersion, $script:SoportaRutaLarga)
    try {
        # Sin WMI: en algunos WinPE (visto en un portátil de prueba) System.Management provoca un
        # AccessViolation que no se puede capturar y cierra PowerShell.
        Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
        $ram = [int64](New-Object Microsoft.VisualBasic.Devices.ComputerInfo).TotalPhysicalMemory
        Write-Log ("Memoria RAM: {0}" -f (Format-Bytes $ram))
        if ($ram -lt 6GB) { Write-Log 'Menos de 6 GB de RAM: ClamAV puede ir lento o fallar al cargar las firmas.' -Nivel AVISO }
    } catch { }
    $Ctx.DiscoUsb = Get-NumeroDiscoDeLetra $RutaRespaldo
    if ((Get-NumeroDiscoDeLetra $RutaHerramientas) -ne $Ctx.DiscoUsb) { throw 'HERRAMIENTAS y RESPALDO no están en el mismo USB.' }
    # El USB se identifica por su firma única sellada en el ancla (no solo por marcadores)
    $idEsperado = Get-FirmaDiscoUsbEsperada
    if ($null -ne $idEsperado) {
        $idReal = [string](Get-DetalleDiscoDp -Numero $Ctx.DiscoUsb).Id
        $idEspTxt = '{0:X8}' -f $idEsperado
        if ($idReal -ne $idEspTxt) { throw ('El USB de RESPALDO no es el sellado en el ancla (firma {0} vs {1}).' -f $idReal, $idEspTxt) }
        Write-Log ("Identidad del USB confirmada (firma {0})." -f $idReal) -Nivel OK
    } elseif ($esWinPE) { throw 'Falta X:\Ancla\usb-id.txt: reconstruya el USB con la versión actual de Crear-USB.ps1.' }
    $secureBoot = Get-EstadoSecureBoot
    Write-Log ("Secure Boot: {0}" -f $secureBoot)
    if ($secureBoot -ne 'ACTIVO') { Write-Log 'Secure Boot no está activo: la cadena de arranque no está verificada por el firmware.' -Nivel AVISO }
    Write-Log ("USB de trabajo: disco #{0} (HERRAMIENTAS {1}, RESPALDO {2}) - libre: {3}" -f $Ctx.DiscoUsb, $RutaHerramientas, $RutaRespaldo, (Format-Bytes (Get-EspacioLibre $RutaRespaldo)))
    Stop-Fase

    # =======================================================================
    # FASE 1 - Detección, confirmación y montaje en SOLO LECTURA
    # =======================================================================
    Start-Fase 'FASE 1 - Detección de discos y montaje en SOLO LECTURA'
    $discos = Show-Discos -NumeroUsb $Ctx.DiscoUsb
    $candidatos = @($discos | Where-Object { $_.Number -ne $Ctx.DiscoUsb })
    if ($candidatos.Count -eq 0) {
        throw 'No se ve ningún disco interno. Si el equipo usa Intel VMD/RST o RAID, agregue el controlador a WinPE (ver GUIA, sección Problemas).'
    }
    $numero = $candidatos[0].Number
    if ($candidatos.Count -gt 1) {
        while ($true) {
            $r = [string](Read-Host ('Número del disco a analizar (normalmente el que tiene Windows) [{0}]' -f $numero))
            if ($r.Trim() -eq '') { break }
            $n = 0
            if ([int]::TryParse($r, [ref]$n) -and @($candidatos | ForEach-Object { $_.Number }) -contains $n) { $numero = $n; break }
            Write-Host 'Número no válido.' -ForegroundColor Yellow
        }
    }
    $Ctx.DiscoObjetivo = $numero
    $Ctx.DiscoInfo = $discos | Where-Object { $_.Number -eq $numero } | Select-Object -First 1
    Write-Host ''
    Write-Host ('Volúmenes del disco #{0} (si está fuera de línea aparecen al montarlo):' -f $numero) -ForegroundColor Cyan
    foreach ($v in @($Ctx.DiscoInfo.Volumenes)) {
        Write-Host ('  Volumen {0}: {1,10}  {2,-6} {3}' -f $v.Num, (Format-Bytes $v.Tamano), $v.Fs, $v.Info)
    }
    Write-Host ''
    Write-Host 'RESUMEN PARA CONFIRMAR' -ForegroundColor Cyan
    Write-Host ('  Disco a analizar : #{0} {1} ({2})' -f $numero, $Ctx.DiscoInfo.FriendlyName, (Format-Bytes $Ctx.DiscoInfo.Size))
    Write-Host ('  Se pondrá en     : SOLO LECTURA (no se escribirá nada en él)')
    Write-Host ('  USB herramientas : {0}   USB respaldo: {1}  (disco #{2})' -f $RutaHerramientas, $RutaRespaldo, $Ctx.DiscoUsb)
    if (-not (Read-Confirmacion 'Confirme que el disco y el USB son correctos')) { throw 'Cancelado por el usuario.' }

    [void](Set-DiscoSoloLectura -Numero $numero -NumeroUsb $Ctx.DiscoUsb)
    $soloLectura = Test-DiscoSoloLectura -Numero $numero
    Write-Log ("Disco #{0} en SOLO LECTURA: {1}" -f $numero, $soloLectura) -Nivel OK
    if (-not $soloLectura) { throw 'El disco no quedó en solo lectura. Se detiene por seguridad.' }

    $letras = @(Get-LetrasDeDisco -Numero $numero)
    Write-Log ("Volúmenes con letra en el disco #{0}: {1}" -f $numero, ($letras -join ', '))
    if ($letras.Count -eq 0) {
        Write-DiagnosticoDp -Numero $numero -Motivo 'sin letras'
        throw 'Windows no asignó letra a ninguna partición del disco (ver Registros\principal.log).'
    }
    Invoke-DesbloqueoBitLocker -Letras $letras
    $Ctx.Volumenes = @($letras | Where-Object { Test-Path -LiteralPath ($_ + '\') })
    if ($Ctx.Volumenes.Count -eq 0) {
        Write-DiagnosticoDp -Numero $numero -Motivo 'volúmenes ilegibles'
        foreach ($l in $letras) {
            $rb = Invoke-Nativo 'manage-bde.exe' @('-status', $l)
            foreach ($x in $rb.Salida) { if ($x) { Write-Log ('  bde> ' + $x) -SoloArchivo } }
        }
        throw ('Ningún volumen del disco es legible ({0}). ¿BitLocker bloqueado o sistema de archivos dañado? Ver Registros\principal.log.' -f ($letras -join ', '))
    }
    Write-Log ("Volúmenes legibles: {0}" -f ($Ctx.Volumenes -join ', '))

    $conWindows = @($Ctx.Volumenes | Where-Object { [System.IO.File]::Exists("$_\Windows\System32\config\SYSTEM") })
    if ($conWindows.Count -gt 1) {
        $op = Read-Opcion -Pregunta ('Hay varias instalaciones de Windows ({0}). Escriba la letra de la principal' -f ($conWindows -join ', ')) -Opciones @($conWindows | ForEach-Object { $_.Substring(0, 1).ToUpperInvariant() }) -PorDefecto $conWindows[0].Substring(0, 1)
        $Ctx.VolWindows = $op + ':'
    } elseif ($conWindows.Count -eq 1) {
        $Ctx.VolWindows = $conWindows[0]
    } else {
        Write-Log 'No se encontró una instalación de Windows: se tratará como disco de datos (sin análisis de persistencia ni perfiles).' -Nivel AVISO
    }

    if ($Ctx.VolWindows) {
        $vw = $Ctx.VolWindows
        Mount-HiveOffline -Origen "$vw\Windows\System32\config\SOFTWARE" -Nombre 'OFF_SOFTWARE' -CarpetaTrabajo $Ctx.Dirs.Trabajo
        Mount-HiveOffline -Origen "$vw\Windows\System32\config\SYSTEM" -Nombre 'OFF_SYSTEM' -CarpetaTrabajo $Ctx.Dirs.Trabajo
        $Ctx.Sistema = Get-InfoSistemaOffline -VolWindows $vw
        Write-Log ("Equipo: {0} | {1} {2} (build {3}) | letra original {4}:" -f $Ctx.Sistema.Nombre, $Ctx.Sistema.Producto, $Ctx.Sistema.Version, $Ctx.Sistema.Build, $Ctx.Sistema.LetraOriginal) -Nivel OK

        $perfiles = @(Get-PerfilesOffline -VolWindows $vw)
        if ($perfiles.Count -gt 0) {
            Write-Host ''
            Write-Host 'Perfiles de usuario encontrados:' -ForegroundColor Cyan
            for ($i = 0; $i -lt $perfiles.Count; $i++) { Write-Host ('  [{0}] {1}' -f ($i + 1), $perfiles[$i].Nombre) }
            $sel = ([string](Read-Host 'Números a respaldar separados por coma (Enter = todos)')).Trim()
            if ($sel -ne '') {
                $idx = @($sel -split '[,; ]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ - 1 } | Where-Object { $_ -ge 0 -and $_ -lt $perfiles.Count })
                if ($idx.Count -gt 0) { $perfiles = @($idx | ForEach-Object { $perfiles[$_] }) }
            }
            $k = 1
            foreach ($pf in $perfiles) {
                try {
                    Mount-HiveOffline -Origen $pf.NtUser -Nombre ("OFF_NTUSER_{0}" -f $k) -CarpetaTrabajo $Ctx.Dirs.Trabajo
                    $pf.Hive = 'OFF_NTUSER_{0}' -f $k
                } catch { Add-RegistroError -Fase 'Detección' -Ruta $pf.NtUser -Mensaje $_.Exception.Message }
                $k++
            }
        }
        $Ctx.Perfiles = $perfiles
    } else {
        $Ctx.Sistema = [pscustomobject]@{ Nombre = '(disco de datos)'; Producto = ''; Version = ''; Build = ''; LetraOriginal = 'C'; ControlSet = 'ControlSet001'; SystemRoot = '' }
    }
    $Ctx.Carpetas = @(Get-CarpetasRespaldo -Ctx $Ctx)
    if (-not (Read-Confirmacion 'Comenzar el análisis (puede durar varias horas)')) { throw 'Cancelado por el usuario.' }
    Stop-Fase

    # =======================================================================
    # FASE 2 - Revisión del disco (sin reparar) y SMART
    # =======================================================================
    Start-Fase 'FASE 2 - Revisión del disco (chkdsk sin reparar) y SMART'
    Assert-SoloLectura -Numero $Ctx.DiscoObjetivo
    $salud = Get-SaludDisco -Numero $numero -RutaHerramientas $RutaHerramientas -CarpetaRegistros $Ctx.Dirs.Registros
    Write-Log ("Salud SMART: {0} ({1})" -f $salud.Veredicto, $salud.Fuente)
    foreach ($d in $salud.Detalles) { Write-Log ('  ' + $d) }
    if (@('MALO', 'DUDOSO', 'DESCONOCIDO') -contains $salud.Veredicto) {
        Write-Host ''
        if ($salud.Veredicto -eq 'DESCONOCIDO') {
            Write-Host 'No se pudo leer la salud (SMART) del disco en este equipo.' -ForegroundColor Yellow
            Write-Host 'Si Windows dejó de arrancar, el disco podría estar fallando: conviene leerlo lo mínimo.' -ForegroundColor Yellow
        } else {
            Write-Host 'El disco muestra señales de fallo. Cada lectura completa lo desgasta más.' -ForegroundColor Yellow
        }
        Write-Host '  N = normal (escaneo y hash de todo el disco)' -ForegroundColor Yellow
        Write-Host '  R = RESCATE (recomendado): chkdsk se omite; escaneo y hash SOLO de las carpetas a respaldar' -ForegroundColor Yellow
        Write-Host '  S = salir (para clonar el disco primero con otra herramienta)' -ForegroundColor Yellow
        $op = Read-Opcion -Pregunta 'Opción [R]' -Opciones @('N', 'R', 'S') -PorDefecto 'R'
        if ($op -eq 'S') { throw 'El usuario decidió detenerse para clonar el disco primero.' }
        if ($op -eq 'R') { $Ctx.Modo = 'Rescate' }
    }
    if ($Ctx.Modo -eq 'Normal') {
        $chk = @(Invoke-RevisionSistemaArchivos -Letras $Ctx.Volumenes -CarpetaRegistros $Ctx.Dirs.Registros)
    } else { Write-Log 'Modo rescate: se omite chkdsk para no estresar el disco.' -Nivel AVISO }
    Stop-Fase

    # =======================================================================
    # FASE 3 - Escaneo de malware sin conexión
    # =======================================================================
    Start-Fase 'FASE 3 - Escaneo antivirus sin conexión (ClamAV + detecciones Defender)'
    Assert-SoloLectura -Numero $Ctx.DiscoObjetivo
    $infoClam = Get-InfoClamAV -RutaHerramientas $RutaHerramientas
    if (-not $infoClam.Disponible) {
        Write-Log ('ClamAV no disponible: {0}' -f $infoClam.Motivo) -Nivel ERROR
        if (-not (Read-Confirmacion 'Continuar SIN antivirus (el respaldo no quedará verificado como limpio)' 'SIN ANTIVIRUS')) { throw 'Detenido: falta ClamAV/firmas. Ejecute Actualizar-Firmas.ps1 en el PC técnico.' }
    } else {
        Write-Log ("Motor y firmas: {0}" -f $infoClam.Version)
        $m = [regex]::Match([string]$infoClam.Version, '/(?:\w{3}) (\w{3})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\d{4})\s*$')
        if ($m.Success) {
            $fecha = [DateTime]::MinValue
            $txt = '{0} {1} {2} {3}' -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value, $m.Groups[4].Value
            if ([DateTime]::TryParseExact($txt, 'MMM d HH:mm:ss yyyy', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$fecha)) {
                $dias = [int]((Get-Date) - $fecha).TotalDays
                Write-Log ("Antigüedad de las firmas: {0} días (fecha del reloj de WinPE: {1})" -f $dias, (Get-Date -Format 'yyyy-MM-dd'))
                if ($dias -gt [int]$Ctx.Config.DiasMaxAntiguedadFirmas) {
                    $firmasAntiguas = $true
                    Write-Log ("Las firmas tienen más de {0} días." -f $Ctx.Config.DiasMaxAntiguedadFirmas) -Nivel AVISO
                    if (-not (Read-Confirmacion 'Continuar con firmas antiguas')) { throw 'Detenido: actualice las firmas con Actualizar-Firmas.ps1.' }
                }
            }
        }
        $objetivos = @()
        if ($Ctx.Modo -eq 'Normal') { $objetivos = @($Ctx.Volumenes | ForEach-Object { $_ + '\' }) }
        else { $objetivos = @($Ctx.Carpetas | ForEach-Object { $_.Origen }) }
        $resClam = Invoke-EscaneoClamAV -Objetivos $objetivos -InfoClamAV $infoClam -Config $Ctx.Config -CarpetaRegistros $Ctx.Dirs.Registros -CarpetaTemporal $Ctx.Dirs.Tmp
        $antivirusEjecutado = $true
        Write-Log ("ClamAV: {0:N0} archivos escaneados, {1} detecciones, {2} errores de lectura." -f $resClam.Escaneados, $resClam.Infectados, $resClam.Errores) -Nivel OK
    }
    $externas = Import-DeteccionesExternas -RutaRespaldo $RutaRespaldo -LetrasObjetivo $Ctx.Volumenes
    Stop-Fase

    # =======================================================================
    # FASE 4 - Persistencia
    # =======================================================================
    Start-Fase 'FASE 4 - Revisión de persistencia (Inicio, Run, tareas, servicios, controladores)'
    Assert-SoloLectura -Numero $Ctx.DiscoObjetivo
    if ($Ctx.VolWindows) {
        $persist = @(Invoke-AnalisisPersistencia -VolWindows $Ctx.VolWindows -InfoSistema $Ctx.Sistema -Perfiles $Ctx.Perfiles -CarpetaDatos $Ctx.Dirs.Datos)
        $vwEsc = [regex]::Escape($Ctx.VolWindows)
        foreach ($hz in $persist) {
            if ($hz.Severidad -ne 'Alta') { continue }
            Write-Log ("PERSISTENCIA ALTA: {0} | {1} | {2}" -f $hz.Categoria, $hz.Nombre, $hz.Motivos) -Nivel DET
            foreach ($o in @($hz.Objetivos)) {
                # Los binarios del propio Windows (rundll32, powershell...) no se ponen en cuarentena
                if ($o -match "(?i)^$vwEsc\\Windows\\(System32|SysWOW64)\\") { continue }
                if (Test-ArchivoExiste $o) {
                    Add-Sospechoso -Ruta $o -Motivo ('Persistencia ALTA: {0} "{1}" ({2})' -f $hz.Categoria, $hz.Nombre, $hz.Motivos) -Motor 'Persistencia' -Severidad 'Alta'
                }
            }
        }
        $nA = @($persist | Where-Object { $_.Severidad -eq 'Alta' }).Count
        $nM = @($persist | Where-Object { $_.Severidad -eq 'Media' }).Count
        Write-Log ("Persistencia: {0} alta, {1} media, {2} entradas revisadas en total." -f $nA, $nM, $persist.Count) -Nivel OK
    } else { Write-Log 'Sin instalación de Windows: fase omitida.' -Nivel AVISO }
    Dismount-HivesOffline
    Stop-Fase

    # =======================================================================
    # FASE 5 - Inventario SHA-256
    # =======================================================================
    Start-Fase 'FASE 5 - Inventario y SHA-256 de los archivos (+ heurísticas)'
    Assert-SoloLectura -Numero $Ctx.DiscoObjetivo
    $raices = @()
    if ($Ctx.Modo -eq 'Normal' -and [string]$Ctx.Config.HashAlcance -eq 'TodoElDisco') { $raices = @($Ctx.Volumenes | ForEach-Object { $_ + '\' }) }
    else { $raices = @($Ctx.Carpetas | ForEach-Object { $_.Origen }) }
    $inv = Invoke-Inventario -Ctx $Ctx -Raices $raices
    Stop-Fase

    # =======================================================================
    # FASE 6 - Cuarentena y copia
    # =======================================================================
    Start-Fase 'FASE 6 - Cuarentena y copia del respaldo (robocopy)'
    Assert-SoloLectura -Numero $Ctx.DiscoObjetivo
    $filasCuar = @(Invoke-Cuarentena -CarpetaCuarentena $Ctx.Dirs.Cuarentena -CarpetaDatos $Ctx.Dirs.Datos -HashPorRuta $inv.HashPorRuta -MaxMB ([int]$Ctx.Config.CuarentenaMaxMB))
    $hashesCuar = @{}
    foreach ($q in $filasCuar) { if ($q.SHA256) { $hashesCuar[[string]$q.SHA256] = $true } }
    Write-Log ("Elementos en cuarentena: {0}" -f @($filasCuar | Where-Object { $_.Estado -like 'EN_CUARENTENA*' -or $_.Estado -like 'SOLO_REGISTRO*' }).Count)
    if (Confirm-EspacioDisponible -Ctx $Ctx) {
        Invoke-CopiaRespaldo -Ctx $Ctx
    } else {
        foreach ($c in $Ctx.Carpetas) { $c.Incluida = $false; $c.ResultadoCopia = 'No copiado (el usuario canceló por espacio)' }
        Write-Log 'Copia cancelada por falta de espacio.' -Nivel AVISO
    }
    Stop-Fase

    # =======================================================================
    # FASE 7 - Verificación de la copia
    # =======================================================================
    Start-Fase 'FASE 7 - Verificación SHA-256 origen vs destino'
    Assert-SoloLectura -Numero $Ctx.DiscoObjetivo
    $verif = Invoke-VerificacionCopia -Ctx $Ctx -HashesCuarentena $hashesCuar
    Stop-Fase
} catch {
    $abortado = $true
    Add-RegistroError -Fase 'General' -Ruta '' -Mensaje $_.Exception.Message
    Write-Log ("Proceso detenido: {0}" -f $_.Exception.Message) -Nivel ERROR
} finally {
    try { Dismount-HivesOffline } catch { }
}

# ===========================================================================
# FASE 8 - Reporte (se genera siempre, aunque el proceso se haya detenido)
# ===========================================================================
Start-Fase 'FASE 8 - Reporte'
try {
    $rv = Invoke-Nativo 'powershell.exe' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'X:\Ancla\Iniciar.ps1', '-SoloVerificar', '-Herramientas', $RutaHerramientas) -ArchivoSalida (Join-Path $Ctx.Dirs.Registros 'integridad_final.txt')
    if ($rv.Codigo -eq 0) { $integridadFinal = 'CORRECTA' }
    elseif ($rv.Codigo -eq 2) { $integridadFinal = 'CORRECTA (avisos en las bases de firmas)' }
    else { $integridadFinal = 'FALLIDA (ver Registros\integridad_final.txt)' }
} catch { $integridadFinal = 'NO SE PUDO VERIFICAR' }

try {
    Export-ListaCsv -Ruta (Join-Path $Ctx.Dirs.Datos 'errores.csv') -Objetos $script:Errores -Columnas @('Fecha', 'Fase', 'Ruta', 'Mensaje')

    $nDet = 0; if ($resClam) { $nDet = $resClam.Infectados }
    $nDet += $externas
    $pA = @($persist | Where-Object { $_.Severidad -eq 'Alta' }).Count
    $pM = @($persist | Where-Object { $_.Severidad -eq 'Media' }).Count
    $pB = @($persist | Where-Object { $_.Severidad -eq 'Baja' }).Count
    $enCuar = @($filasCuar | Where-Object { $_.Estado -eq 'EN_CUARENTENA' })
    $bytesCuar = [int64]0; foreach ($q in $enCuar) { if ($q.Tamano) { $bytesCuar += [int64]$q.Tamano } }
    $chkErr = @($chk | Where-Object { $_.Ejecutado -and $_.Codigo -eq 3 }).Count
    $tamCaso = [int64]0
    try { foreach ($f in [System.IO.Directory]::EnumerateFiles($caso, '*', [System.IO.SearchOption]::AllDirectories)) { $tamCaso += (New-Object System.IO.FileInfo -ArgumentList $f).Length } } catch { }

    $saludTxt = 'NO EVALUADA'; $saludFuente = ''; $saludDet = @()
    if ($salud) { $saludTxt = $salud.Veredicto; $saludFuente = $salud.Fuente; $saludDet = $salud.Detalles }
    $v = $verif
    if (-not $v) { $v = [pscustomobject]@{ OK = 0; Diferente = 0; Falta = 0; Nube = 0; Excluido = 0; ErrorLectura = 0; Fugas = 0; BytesCopiados = 0 } }

    $nivel = 'VERDE'; $motivos = @()
    if ($abortado) { $nivel = 'ROJO'; $motivos += 'El proceso se detuvo antes de terminar' }
    if ($nDet -gt 0) { $nivel = 'ROJO'; $motivos += ('{0} detecciones de malware' -f $nDet) }
    if ($pA -gt 0) { $nivel = 'ROJO'; $motivos += ('{0} mecanismos de inicio de severidad alta' -f $pA) }
    if ($saludTxt -eq 'MALO') { $nivel = 'ROJO'; $motivos += 'disco con señales de fallo' }
    if ($integridadFinal -notlike 'CORRECTA*') { $nivel = 'ROJO'; $motivos += 'integridad del USB no confirmada' }
    if ($nivel -ne 'ROJO') {
        if ($saludTxt -eq 'DUDOSO' -or $v.Diferente -gt 0 -or $v.Falta -gt 0 -or -not $antivirusEjecutado -or $firmasAntiguas -or $pM -gt 0 -or $enCuar.Count -gt 0) {
            $nivel = 'AMARILLO'
            if ($saludTxt -eq 'DUDOSO') { $motivos += 'advertencias de salud del disco' }
            if ($v.Diferente -gt 0 -or $v.Falta -gt 0) { $motivos += 'archivos sin copiar o con diferencias' }
            if (-not $antivirusEjecutado) { $motivos += 'sin escaneo antivirus' }
            if ($firmasAntiguas) { $motivos += 'firmas antiguas' }
            if ($pM -gt 0) { $motivos += ('{0} entradas de inicio para revisar' -f $pM) }
            if ($enCuar.Count -gt 0) { $motivos += ('{0} archivos sospechosos en cuarentena' -f $enCuar.Count) }
        }
    }
    $texto = 'VERDE: no se encontraron amenazas y el respaldo se verificó correctamente.'
    if ($nivel -eq 'ROJO') { $texto = 'ROJO: atención requerida - ' + ($motivos -join '; ') + '.' }
    elseif ($nivel -eq 'AMARILLO') { $texto = 'AMARILLO: revisar - ' + ($motivos -join '; ') + '.' }

    # Datos del reporte: se arman paso a paso (sin $(if ...) dentro de un literal
    # [pscustomobject], que en un WinPE de prueba dio "Argument types do not match").
    $infoDisco = $Ctx.DiscoInfo
    $P = [ordered]@{}
    $P['Fecha'] = (Get-Date -Format 'yyyy-MM-dd HH:mm')
    $P['Duracion'] = (Format-Duracion ((Get-Date) - $inicioTotal))
    $P['Modo'] = [string]$Ctx.Modo
    $P['Equipo'] = '(desconocido)'; $P['Producto'] = ''; $P['Version'] = ''; $P['Build'] = ''
    if ($Ctx.Sistema) {
        $P['Equipo'] = [string]$Ctx.Sistema.Nombre; $P['Producto'] = [string]$Ctx.Sistema.Producto
        $P['Version'] = [string]$Ctx.Sistema.Version; $P['Build'] = [string]$Ctx.Sistema.Build
    }
    $P['DiscoNumero'] = [string]$Ctx.DiscoObjetivo
    $P['DiscoModelo'] = ''; $P['DiscoTamano'] = ''
    if ($infoDisco) { $P['DiscoModelo'] = [string]$infoDisco.FriendlyName; $P['DiscoTamano'] = (Format-Bytes ([double]$infoDisco.Size)) }
    $P['SoloLectura'] = $soloLectura
    $P['Volumenes'] = @($Ctx.Volumenes)
    $P['Veredicto'] = $texto; $P['NivelVeredicto'] = $nivel
    $P['Salud'] = $saludTxt; $P['SaludFuente'] = $saludFuente; $P['SaludDetalles'] = @($saludDet)
    $P['Chkdsk'] = @($chk); $P['ChkdskErrores'] = $chkErr
    $P['ClamVersion'] = 'NO DISPONIBLE'
    if ($infoClam -and $infoClam.Disponible) { $P['ClamVersion'] = [string]$infoClam.Version }
    $P['Escaneados'] = 0; $P['ErroresEscaneo'] = 0
    if ($resClam) { $P['Escaneados'] = $resClam.Escaneados; $P['ErroresEscaneo'] = $resClam.Errores }
    $P['Detecciones'] = $nDet; $P['Externas'] = $externas
    $P['Heuristicas'] = 0
    if ($inv) { $P['Heuristicas'] = $inv.Stats.Heuristicas }
    $P['EnCuarentena'] = $enCuar.Count; $P['BytesCuarentena'] = (Format-Bytes ([double]$bytesCuar))
    $P['ListaCuarentena'] = @($filasCuar | Where-Object { $_.Estado -ne '' })
    $P['PersistenciaAlta'] = $pA; $P['PersistenciaMedia'] = $pM; $P['PersistenciaBaja'] = $pB
    $P['ListaPersistencia'] = @($persist | Where-Object { @('Alta', 'Media') -contains $_.Severidad })
    $P['Carpetas'] = @($Ctx.Carpetas)
    $P['VerifOK'] = $v.OK; $P['VerifDiferentes'] = $v.Diferente; $P['VerifFaltan'] = $v.Falta; $P['VerifNube'] = $v.Nube
    $P['VerifExcluidos'] = $v.Excluido; $P['VerifErrores'] = $v.ErrorLectura; $P['Fugas'] = $v.Fugas
    $P['BytesCopiados'] = (Format-Bytes ([double]$v.BytesCopiados))
    $P['EspacioCaso'] = (Format-Bytes ([double]$tamCaso))
    $P['EspacioLibre'] = ''
    try { $P['EspacioLibre'] = (Format-Bytes ([double](Get-EspacioLibre $RutaRespaldo))) } catch { }
    $P['IntegridadInicial'] = $IntegridadInicial; $P['IntegridadFinal'] = $integridadFinal
    $P['IntegridadFinalOk'] = ($integridadFinal -like 'CORRECTA*')
    $P['SecureBoot'] = [string]$secureBoot
    $P['Marcados'] = 0; $P['Enlaces'] = 0
    if ($verif) { $P['Marcados'] = $verif.Marcados; $P['Enlaces'] = $verif.Enlaces }
    $P['Huella'] = $Huella
    $P['AntivirusEjecutado'] = $antivirusEjecutado; $P['FirmasAntiguas'] = $firmasAntiguas
    $P['TotalErrores'] = $script:Errores.Count; $P['ListaErrores'] = $script:Errores.ToArray()
    $R = New-Object -TypeName PSObject -Property $P
    [void](New-Reporte -Ctx $Ctx -R $R)
    Write-Log ("Reporte: {0}" -f (Join-Path $Ctx.Dirs.Reporte 'reporte.html')) -Nivel OK
    $colorFinal = 'Green'; if ($nivel -eq 'ROJO') { $colorFinal = 'Red' } elseif ($nivel -eq 'AMARILLO') { $colorFinal = 'Yellow' }
    Write-Host ''
    Write-Host $texto -ForegroundColor $colorFinal
} catch {
    Write-Log ("No se pudo generar el reporte completo: {0}" -f $_.Exception.Message) -Nivel ERROR
    Write-Log ("  en la línea {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, ([string]$_.InvocationInfo.Line).Trim()) -Nivel ERROR -SoloArchivo
    Write-Log ("  pila: {0}" -f $_.ScriptStackTrace) -Nivel ERROR -SoloArchivo
    # Reporte mínimo para no quedarse sin nada
    try {
        New-Item -ItemType Directory -Path $Ctx.Dirs.Reporte -Force | Out-Null
        $min = @('REPORTE MÍNIMO (falló el reporte completo)', ('Fecha: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm')),
            ('Error del reporte: {0}' -f $_.Exception.Message), ('Proceso detenido antes de terminar: {0}' -f $abortado),
            ('Errores registrados: {0}' -f $script:Errores.Count))
        foreach ($x in $script:Errores.ToArray()) { $min += ('  [{0}] {1} :: {2}' -f $x.Fase, $x.Ruta, $x.Mensaje) }
        $min += 'Registro completo: Registros\principal.log'
        [System.IO.File]::WriteAllLines((Join-Path $Ctx.Dirs.Reporte 'reporte.txt'), [string[]]$min, $script:Utf8ConBom)
    } catch { }
}

# Limpieza de NUESTROS archivos temporales en el USB (copias de hives y
# temporales de ClamAV). No toca nada del equipo analizado.
try {
    if (Test-Path -LiteralPath $Ctx.Dirs.Trabajo) { Remove-Item -LiteralPath $Ctx.Dirs.Trabajo -Recurse -Force -ErrorAction Stop }
} catch { Write-Log ("No se pudo limpiar la carpeta de trabajo: {0}" -f $_.Exception.Message) -Nivel AVISO }
Stop-Fase
try { Stop-Transcript | Out-Null } catch { }
Write-Host ''
Write-Host ("Caso guardado en: {0}" -f $caso) -ForegroundColor Cyan
Write-Host 'Lleve el USB a un PC sano para leer Reporte\reporte.html. NO abra el respaldo en el equipo analizado.' -ForegroundColor Cyan
if ($abortado) { exit 1 } else { exit 0 }
