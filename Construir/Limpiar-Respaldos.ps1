<#
.SYNOPSIS
    Deja la USB TITAN lista para otro equipo: borra los casos (respaldos, cuarentena,
    registros e informes) de la partición RESPALDO, y en este PC las listas de
    verificación que nombran archivos de esos casos.
    NO toca TITAN-BOOT ni TITAN-TOOLS, ni LEEME.txt, RESPALDO.marker o la carpeta Entrada.
    Pide escribir BORRAR antes de hacer nada.
#>
$ErrorActionPreference = 'Stop'
$aqui = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$repo = Split-Path -Path $aqui -Parent

# La partición RESPALDO de TITAN: etiqueta TITAN-USB + su marcador
$raiz = $null
foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
    if (-not $d.IsReady) { continue }
    $r = $d.RootDirectory.FullName
    if ($d.VolumeLabel -eq 'TITAN-USB' -and (Test-Path -LiteralPath (Join-Path $r 'RESPALDO.marker'))) { $raiz = $r; break }
}
if (-not $raiz) { Write-Host 'No se encontró la partición TITAN-USB (con RESPALDO.marker). Conecte la USB TITAN.' -ForegroundColor Red; exit 1 }
$casos = Join-Path $raiz 'Casos'

$aBorrar = @(Get-ChildItem -LiteralPath $casos -Directory -Force -ErrorAction SilentlyContinue)
$listasPc = @(Get-ChildItem -LiteralPath $repo -File -Filter 'verificacion_respaldo_*' -ErrorAction SilentlyContinue)

Write-Host ''
Write-Host ('USB TITAN, partición de respaldos: {0}' -f $raiz) -ForegroundColor Cyan
Write-Host 'Se BORRARÁN estas carpetas de casos (respaldo, cuarentena, registros, informes):' -ForegroundColor Yellow
if ($aBorrar.Count -eq 0) { Write-Host '  (no hay ninguna)' }
foreach ($c in $aBorrar) { Write-Host ('  {0}' -f $c.FullName) }
Write-Host 'Y en este PC, las listas de verificación con nombres de esos archivos:' -ForegroundColor Yellow
if ($listasPc.Count -eq 0) { Write-Host '  (no hay ninguna)' }
foreach ($l in $listasPc) { Write-Host ('  {0}' -f $l.FullName) }
Write-Host ''
Write-Host 'NO se tocan: TITAN-BOOT, TITAN-TOOLS, LEEME.txt, RESPALDO.marker ni la carpeta Entrada.' -ForegroundColor Green
Write-Host ''
if ($aBorrar.Count -eq 0 -and $listasPc.Count -eq 0) { Write-Host 'No hay nada que borrar.'; exit 0 }
$resp = ([string](Read-Host 'Escriba BORRAR para confirmar (cualquier otra cosa cancela)')).Trim().ToUpperInvariant()
if ($resp -ne 'BORRAR') { Write-Host 'Cancelado. No se borró nada.' -ForegroundColor Yellow; exit 0 }

$fallos = [System.Collections.Generic.List[string]]::new()
foreach ($c in $aBorrar) {
    # rd con \\?\ admite rutas de más de 260 caracteres
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'   # rd escribe en stderr: no debe detener el script
    & cmd.exe /d /c ('rd /s /q "\\?\{0}"' -f $c.FullName) 2>&1 | Out-Null
    $ErrorActionPreference = $eap
    if (Test-Path -LiteralPath $c.FullName) { $fallos.Add($c.FullName) } else { Write-Host ('  Borrado: {0}' -f $c.Name) -ForegroundColor Green }
}
foreach ($l in $listasPc) {
    try { Remove-Item -LiteralPath $l.FullName -Force; Write-Host ('  Borrado: {0}' -f $l.Name) -ForegroundColor Green }
    catch { $fallos.Add($l.FullName) }
}

Write-Host ''
$quedan = @(Get-ChildItem -LiteralPath $casos -Force -ErrorAction SilentlyContinue)
if ($fallos.Count -eq 0 -and $quedan.Count -eq 0) {
    Write-Host 'LISTO: la carpeta Casos de la USB quedó vacía y TITAN está intacta.' -ForegroundColor Green
    exit 0
}
Write-Host 'No se pudo borrar todo:' -ForegroundColor Red
$fallos | ForEach-Object { Write-Host ('  {0}' -f $_) -ForegroundColor Red }
$quedan | ForEach-Object { Write-Host ('  queda: {0}' -f $_.FullName) -ForegroundColor Red }
Write-Host 'Si Windows dice que el archivo o directorio está dañado, la partición necesita una revisión (chkdsk). Ejecute REPARAR-RESPALDOS.bat.' -ForegroundColor Yellow
exit 1
