#Requires -RunAsAdministrator
<#
    Probar-TITAN.ps1 - Simulacro COMPLETO del análisis en ESTE PC, sin tocar
    ningún disco real:
      - Se arma un "disco falso" en la carpeta temporal (perfil de usuario con
        documentos, un archivo con doble extensión y copias del registro hechas
        con "reg save").
      - Se ejecutan sobre él las mismas funciones que usa TITAN en el equipo analizado:
        perfiles, carpetas a respaldar, persistencia, inventario SHA-256,
        cuarentena, copia con robocopy, verificación y reporte final.
      - diskpart solo se usa para LEER (list / detail).
    Todo lo temporal se borra al terminar. Resultado: prueba_titan.txt
#>
$ErrorActionPreference = 'Stop'
$aqui = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$repo = Split-Path -Path $aqui -Parent
$scripts = Join-Path $repo 'Herramientas\Scripts'
$lib = Join-Path $scripts 'Lib'
$salida = Join-Path $repo 'prueba_titan.txt'
try { Start-Transcript -Path $salida -Force | Out-Null } catch { }
foreach ($n in @('Comun', 'Disco', 'Malware', 'Persistencia', 'Respaldo', 'Reporte')) { . (Join-Path $lib ($n + '.ps1')) }

# En el simulacro nadie responde preguntas: Enter (opción por defecto) a todo
function Read-Host {
    param([Parameter(ValueFromRemainingArguments = $true)]$Resto)
    return ''
}

$script:Fallos = 0
function Show-ErrorCompleto {
    param($E, [string]$Prueba)
    $script:Fallos++
    Write-Host ('FALLO en {0}: {1}' -f $Prueba, $E.Exception.Message) -ForegroundColor Red
    Write-Host ('  Tipo: {0}' -f $E.Exception.GetType().FullName)
    Write-Host ('  Posición: {0}' -f $E.InvocationInfo.PositionMessage)
    Write-Host ('  Pila: {0}' -f $E.ScriptStackTrace)
    Write-Host ('  Detalle .NET: {0}' -f $E.Exception.ToString())
}
function Write-Prueba {
    param([string]$T)
    Write-Host ''
    Write-Host ('=== ' + $T + ' ===') -ForegroundColor Cyan
}

$tmp = Join-Path $env:TEMP ('titan_prueba_{0}' -f [guid]::NewGuid().ToString('N'))
$caso = Join-Path $tmp 'Caso'
# El disco falso va en la raíz de C: (como un disco real), no dentro de Temp,
# para que la revisión de persistencia no lo confunda con una carpeta temporal.
$disco = Join-Path ($env:SystemDrive + '\') ('TITAN_disco_prueba_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$Ctx = @{
    RutaHerramientas = 'U:\'; RutaRespaldo = $tmp; Config = $null; Modo = 'Normal'
    Dirs = @{ Caso = $caso; Respaldo = "$caso\Respaldo"; Cuarentena = "$caso\Cuarentena"; Registros = "$caso\Registros"
        Datos = "$caso\Datos"; Reporte = "$caso\Reporte"; Trabajo = "$caso\Trabajo"; Tmp = "$caso\Trabajo\tmp" }
    DiscoUsb = -1; DiscoObjetivo = -1; DiscoInfo = $null; Volumenes = @(); VolWindows = $null; Sistema = $null
    Perfiles = @(); Carpetas = @(); Tiempos = [ordered]@{}
}
foreach ($d in $Ctx.Dirs.Values) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
Initialize-Registro -ArchivoLog (Join-Path $Ctx.Dirs.Registros 'principal.log')
Initialize-RutasLargas
$Ctx.Config = Get-Content -LiteralPath (Join-Path $scripts 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$RutaRespaldo = $tmp; $RutaHerramientas = 'U:\'; $Huella = 'PRUEBA'; $IntegridadInicial = 'CORRECTA'
$inicioTotal = Get-Date
$resClam = $null; $infoClam = $null; $externas = 0; $chk = @(); $salud = $null
$persist = @(); $inv = $null; $filasCuar = @(); $verif = $null
$antivirusEjecutado = $false; $firmasAntiguas = $false; $soloLectura = $true
$integridadFinal = 'CORRECTA'; $secureBoot = 'INACTIVO'; $abortado = $false

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 1: CSV con la lista de errores'
try {
    Add-RegistroError -Fase 'Prueba' -Ruta 'C:\ruta;con "comillas"' -Mensaje 'Error de prueba con acentos: ñandú' -Silencioso
    Export-ListaCsv -Ruta (Join-Path $Ctx.Dirs.Datos 'errores.csv') -Objetos $script:Errores -Columnas @('Fecha', 'Fase', 'Ruta', 'Mensaje')
    Get-Content -LiteralPath (Join-Path $Ctx.Dirs.Datos 'errores.csv') | ForEach-Object { Write-Host ('  ' + $_) }
    Write-Host 'OK' -ForegroundColor Green
} catch { Show-ErrorCompleto $_ 'PRUEBA 1' }

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 2: diskpart (solo lectura) y salud del USB'
try {
    foreach ($x in @(Get-ListaDiscosDp)) {
        $dd = Get-DetalleDiscoDp -Numero $x.Number -TamanoTexto $x.Tamano
        Write-Host ('Disco {0}: {1} | {2} | id {3} | {4} volúmenes' -f $x.Number, $dd.FriendlyName, $dd.BusType, $dd.Id, @($dd.Volumenes).Count)
    }
    # La USB TITAN se busca por la etiqueta de su particion de respaldo (<Nombre>-USB).
    $volUsb = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.FileSystemLabel -like '*-USB' }) | Select-Object -First 1
    if (-not $volUsb) {
        Write-Host 'No hay una USB TITAN conectada: se omite la salud del USB (no es un fallo).' -ForegroundColor Yellow
    } else {
        $letraUsb = '{0}:\' -f $volUsb.DriveLetter
        $volTools = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.FileSystemLabel -like '*-TOOLS' }) | Select-Object -First 1
        $rutaTools = if ($volTools) { '{0}:\' -f $volTools.DriveLetter } else { $letraUsb }
        $nUsb = Get-NumeroDiscoDeLetra $letraUsb
        Write-Host ('{0} está en el disco #{1}' -f $letraUsb, $nUsb)
        Write-Host ('Letras de ese disco: {0}' -f (@(Get-LetrasDeDisco -Numero $nUsb) -join ', '))
        $salud = Get-SaludDisco -Numero $nUsb -RutaHerramientas $rutaTools -CarpetaRegistros $Ctx.Dirs.Registros
        Write-Host ('Salud: {0} | fuente: {1} | {2}' -f $salud.Veredicto, $salud.Fuente, ($salud.Detalles -join ' / '))
    }
    Write-Host 'OK' -ForegroundColor Green
} catch { Show-ErrorCompleto $_ 'PRUEBA 2' }

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 3: disco falso (perfil, documentos y copias del registro)'
try {
    $perfil = Join-Path $disco 'Users\Prueba'
    foreach ($d in @("$disco\Windows\System32\config", "$perfil\Documents\Sub carpeta", "$perfil\Desktop", "$perfil\Pictures", "$perfil\Downloads", "$perfil\Documents\node_modules\x")) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
    Set-Content -LiteralPath "$perfil\Documents\carta.txt" -Value 'Hola, esto es una carta de prueba.' -Encoding UTF8
    Set-Content -LiteralPath "$perfil\Documents\informe ñandú (copia).txt" -Value ('dato;' * 2000) -Encoding UTF8
    Set-Content -LiteralPath "$perfil\Documents\Sub carpeta\tabla.csv" -Value "a;b`r`n1;2" -Encoding UTF8
    Set-Content -LiteralPath "$perfil\Documents\node_modules\x\ignorar.js" -Value '//' -Encoding UTF8
    Set-Content -LiteralPath "$perfil\Desktop\nota.txt" -Value 'nota' -Encoding UTF8
    Set-Content -LiteralPath "$perfil\Desktop\factura.pdf.exe" -Value 'No es un programa: solo texto para probar la heurística de doble extensión.' -Encoding ASCII
    [System.IO.File]::WriteAllBytes("$perfil\Pictures\foto.jpg", [byte[]](0xFF, 0xD8, 0xFF, 0xE0) + [byte[]](1..200))
    $Ctx.Volumenes = @($disco)
    $Ctx.VolWindows = $disco
    foreach ($par in @(@('HKLM\SOFTWARE', "$disco\Windows\System32\config\SOFTWARE"), @('HKLM\SYSTEM', "$disco\Windows\System32\config\SYSTEM"), @('HKCU', "$perfil\NTUSER.DAT"))) {
        $r = Invoke-Nativo 'reg.exe' @('save', $par[0], $par[1], '/y')
        Write-Host ('reg save {0}: código {1}' -f $par[0], $r.Codigo)
        if ($r.Codigo -ne 0) { throw ('reg save falló: ' + ($r.Salida -join ' ')) }
    }
    $Ctx.DiscoObjetivo = 99
    $Ctx.DiscoInfo = [pscustomobject]@{ FriendlyName = 'DISCO FALSO DE PRUEBA'; Size = 512GB; Volumenes = @() }
    Write-Host 'OK' -ForegroundColor Green
} catch { Show-ErrorCompleto $_ 'PRUEBA 3' }

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 4: hives, sistema, perfiles y carpetas a respaldar (FASE 1)'
try {
    $vw = $Ctx.VolWindows
    if (-not $vw) { throw 'El disco falso no se creó (ver PRUEBA 3).' }
    Mount-HiveOffline -Origen "$vw\Windows\System32\config\SOFTWARE" -Nombre 'OFF_SOFTWARE' -CarpetaTrabajo $Ctx.Dirs.Trabajo
    Mount-HiveOffline -Origen "$vw\Windows\System32\config\SYSTEM" -Nombre 'OFF_SYSTEM' -CarpetaTrabajo $Ctx.Dirs.Trabajo
    $Ctx.Sistema = Get-InfoSistemaOffline -VolWindows $vw
    Write-Host ('Equipo: {0} | {1} {2} (build {3}) | letra {4}' -f $Ctx.Sistema.Nombre, $Ctx.Sistema.Producto, $Ctx.Sistema.Version, $Ctx.Sistema.Build, $Ctx.Sistema.LetraOriginal)
    $perfiles = @(Get-PerfilesOffline -VolWindows $vw)
    Write-Host ('Perfiles: {0}' -f (@($perfiles | ForEach-Object { $_.Nombre }) -join ', '))
    $k = 1
    foreach ($pf in $perfiles) {
        Mount-HiveOffline -Origen $pf.NtUser -Nombre ("OFF_NTUSER_{0}" -f $k) -CarpetaTrabajo $Ctx.Dirs.Trabajo
        $pf.Hive = 'OFF_NTUSER_{0}' -f $k
        $k++
    }
    $Ctx.Perfiles = $perfiles
    $Ctx.Carpetas = @(Get-CarpetasRespaldo -Ctx $Ctx)
    foreach ($c in $Ctx.Carpetas) { Write-Host ('  {0} <- {1}' -f $c.Etiqueta, $c.Origen) }
    Write-Host 'OK' -ForegroundColor Green
} catch { Show-ErrorCompleto $_ 'PRUEBA 4' }

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 5: persistencia (FASE 4)'
try {
    $persist = @(Invoke-AnalisisPersistencia -VolWindows $Ctx.VolWindows -InfoSistema $Ctx.Sistema -Perfiles $Ctx.Perfiles -CarpetaDatos $Ctx.Dirs.Datos)
    Write-Host ('{0} entradas | alta {1} | media {2}' -f $persist.Count, @($persist | Where-Object { $_.Severidad -eq 'Alta' }).Count, @($persist | Where-Object { $_.Severidad -eq 'Media' }).Count)
    Write-Host 'OK' -ForegroundColor Green
} catch { Show-ErrorCompleto $_ 'PRUEBA 5' }
try { Dismount-HivesOffline } catch { Show-ErrorCompleto $_ 'PRUEBA 5 (descargar hives)' }

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 6: inventario SHA-256 y heurísticas (FASE 5)'
try {
    $inv = Invoke-Inventario -Ctx $Ctx -Raices @("$disco\Users")
    Write-Host ('{0} archivos | heurísticas {1}' -f $inv.Stats.Archivos, $inv.Stats.Heuristicas)
    Write-Host 'OK' -ForegroundColor Green
} catch { Show-ErrorCompleto $_ 'PRUEBA 6' }

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 7: cuarentena y copia con robocopy (FASE 6)'
try {
    $hp = @{}; if ($inv) { $hp = $inv.HashPorRuta }
    $filasCuar = @(Invoke-Cuarentena -CarpetaCuarentena $Ctx.Dirs.Cuarentena -CarpetaDatos $Ctx.Dirs.Datos -HashPorRuta $hp -MaxMB ([int]$Ctx.Config.CuarentenaMaxMB))
    foreach ($q in $filasCuar) { Write-Host ('  cuarentena: {0} [{1}] {2}' -f $q.Id, $q.Estado, $q.RutaOriginal) }
    $hashesCuar = @{}
    foreach ($q in $filasCuar) { if ($q.SHA256) { $hashesCuar[[string]$q.SHA256] = $true } }
    if (Confirm-EspacioDisponible -Ctx $Ctx) { Invoke-CopiaRespaldo -Ctx $Ctx }
    foreach ($c in $Ctx.Carpetas) { Write-Host ('  {0}: {1}' -f $c.Etiqueta, $c.ResultadoCopia) }
    Write-Host 'OK' -ForegroundColor Green
} catch { Show-ErrorCompleto $_ 'PRUEBA 7' }

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 8: verificación de la copia (FASE 7)'
try {
    if (-not $hashesCuar) { $hashesCuar = @{} }
    $verif = Invoke-VerificacionCopia -Ctx $Ctx -HashesCuarentena $hashesCuar
    Write-Host ('OK={0} diferentes={1} faltan={2} cuarentena={3} marcados={4}' -f $verif.OK, $verif.Diferente, $verif.Falta, $verif.Cuarentena, $verif.Marcados)
    if (Test-Path -LiteralPath "$($Ctx.Dirs.Respaldo)\Prueba\Desktop\factura.pdf.exe") { Write-Host 'ATENCIÓN: el archivo sospechoso llegó al respaldo' -ForegroundColor Red; $script:Fallos++ }
    else { Write-Host 'El archivo sospechoso NO está en el respaldo (correcto).' -ForegroundColor Green }
    Write-Host 'OK' -ForegroundColor Green
} catch { Show-ErrorCompleto $_ 'PRUEBA 8' }

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 10: disco VIRTUAL (VHD) -> solo lectura, en línea, letras, lectura (FASE 1)'
# Se crea un disco virtual de 1 GB en la carpeta temporal y se le aplica la MISMA
# secuencia que al disco del equipo real. Ningún disco real se toca: el disco de prueba se
# identifica como el único disco NUEVO tras conectar el VHD y se comprueba su tamaño.
$vhd = Join-Path $tmp 'disco_prueba.vhdx'
$nVhd = -1
try {
    $antesDp = @(Get-ListaDiscosDp | ForEach-Object { $_.Number })
    $r = Invoke-Diskpart @(('create vdisk file="{0}" maximum=1024 type=expandable' -f $vhd), ('select vdisk file="{0}"' -f $vhd), 'attach vdisk')
    Start-Sleep -Seconds 3
    $nuevos = @(Get-ListaDiscosDp | Where-Object { $antesDp -notcontains $_.Number })
    if ($nuevos.Count -ne 1) { throw ('No se identificó un único disco nuevo tras conectar el VHD (nuevos: {0}).' -f $nuevos.Count) }
    $tam = ConvertFrom-TamanoDiskpart $nuevos[0].Tamano
    if ($tam -lt 900MB -or $tam -gt 1200MB) { throw ('El disco nuevo no mide ~1 GB ({0}): se cancela por seguridad.' -f $nuevos[0].Tamano) }
    $nVhd = [int]$nuevos[0].Number
    Write-Host ('Disco virtual = disco #{0} ({1})' -f $nVhd, $nuevos[0].Tamano)
    $r = Invoke-Diskpart @("select disk $nVhd", 'convert gpt noerr', 'create partition primary', 'format fs=ntfs quick label=PRUEBA', 'assign')
    Start-Sleep -Seconds 3
    $l0 = @(Get-LetrasDeDisco -Numero $nVhd)
    if ($l0.Count -ne 1) { throw ('El volumen de prueba no recibió letra: ' + ($r -join ' | ')) }
    Set-Content -LiteralPath ($l0[0] + '\documento de prueba.txt') -Value 'Contenido de prueba' -Encoding UTF8
    # Simula lo que hace el arranque de TITAN: quitar la letra, desconectar y marcar solo lectura
    [void](Invoke-Diskpart @(('select volume {0}' -f $l0[0].Substring(0, 1)), 'remove noerr'))
    [void](Invoke-Diskpart @("select disk $nVhd", 'offline disk noerr', 'attributes disk set readonly noerr'))
    $d1 = Get-DetalleDiscoDp -Numero $nVhd
    Write-Host ('Estado inicial (como en el equipo real): fuera de línea={0} atributo solo lectura={1} estado actual={2}' -f $d1.IsOffline, $d1.AtributoSoloLectura, $d1.IsReadOnly)
    foreach ($l in (Invoke-Diskpart @("select disk $nVhd", 'detail disk'))) { if ($l -match '(?i)(read|lectura|status|estado)') { Write-Host ('  | ' + $l) } }
    # La función real de TITAN
    [void](Set-DiscoSoloLectura -Numero $nVhd -NumeroUsb 1)
    $d2 = Get-DetalleDiscoDp -Numero $nVhd
    $letrasV = @(Get-LetrasDeDisco -Numero $nVhd)
    Write-Host ('Tras Set-DiscoSoloLectura: fuera de línea={0} solo lectura={1} letras={2}' -f $d2.IsOffline, $d2.IsReadOnly, ($letrasV -join ', '))
    if ($d2.IsOffline) { throw 'El disco virtual quedó FUERA DE LÍNEA (es el fallo visto en un equipo real).' }
    if (-not $d2.IsReadOnly) { throw 'El disco virtual NO quedó en solo lectura.' }
    if ($letrasV.Count -eq 0) { throw 'El volumen no recibió letra.' }
    $lv = $letrasV[0]
    Write-Host ('BitLocker en {0}: {1}' -f $lv, (Get-EstadoBitLocker -Letra $lv))
    $txt = Get-Content -LiteralPath ($lv + '\documento de prueba.txt') -Raw
    Write-Host ('Lectura del documento: "{0}"' -f $txt.Trim())
    $escribio = $true
    try { Set-Content -LiteralPath ($lv + '\no_debe_escribirse.txt') -Value 'x' -ErrorAction Stop } catch { $escribio = $false }
    if ($escribio) { throw 'Se pudo ESCRIBIR en el disco en solo lectura.' }
    Write-Host 'Escritura bloqueada (correcto: el disco está protegido).' -ForegroundColor Green
    Write-Host 'OK' -ForegroundColor Green
} catch { Show-ErrorCompleto $_ 'PRUEBA 10' }
finally {
    Write-Host '--- registro de diskpart de la PRUEBA 10 ---'
    Get-Content -LiteralPath (Join-Path $Ctx.Dirs.Registros 'principal.log') | Where-Object { $_ -match '(offline:|readonly:|online:|dp>|assign|antes de ponerlo)' } | ForEach-Object { Write-Host ('  ' + $_) }
    if ($nVhd -ge 0) { [void](Invoke-Diskpart @("select disk $nVhd", 'attributes disk clear readonly noerr')) }
    [void](Invoke-Diskpart @(('select vdisk file="{0}"' -f $vhd), 'detach vdisk noerr'))
}

# ---------------------------------------------------------------------------
Write-Prueba 'PRUEBA 9: reporte final (FASE 8, mismo código)'
try {
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
    if (Test-Path -LiteralPath (Join-Path $Ctx.Dirs.Reporte 'reporte.html')) { Write-Host 'OK: reporte.html generado' -ForegroundColor Green }
    else { $script:Fallos++; Write-Host 'No se generó reporte.html' -ForegroundColor Red }
} catch { Show-ErrorCompleto $_ 'PRUEBA 9' }
Write-Host '--- registro interno (errores y avisos) ---'
Get-Content -LiteralPath (Join-Path $Ctx.Dirs.Registros 'principal.log') | Where-Object { $_ -match '\[(ERROR|AVISO)' } | ForEach-Object { Write-Host ('  ' + $_) }
Write-Host '--- reporte.txt ---'
if (Test-Path -LiteralPath (Join-Path $Ctx.Dirs.Reporte 'reporte.txt')) { Get-Content -LiteralPath (Join-Path $Ctx.Dirs.Reporte 'reporte.txt') | Select-Object -First 45 | ForEach-Object { Write-Host ('  ' + $_) } }

try { Dismount-HivesOffline } catch { }
foreach ($borrar in @($tmp, $disco)) {
    try { Remove-Item -LiteralPath $borrar -Recurse -Force -ErrorAction Stop } catch { Write-Host ('No se pudo borrar la carpeta temporal {0}' -f $borrar) -ForegroundColor Yellow }
}
Write-Host ''
if ($script:Fallos -eq 0) { Write-Host 'SIMULACRO COMPLETO SIN FALLOS' -ForegroundColor Green } else { Write-Host ('SIMULACRO CON {0} FALLO(S)' -f $script:Fallos) -ForegroundColor Red }
Write-Host ('Resultado guardado en {0}' -f $salida) -ForegroundColor Cyan
try { Stop-Transcript | Out-Null } catch { }
