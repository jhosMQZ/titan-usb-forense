<#
.SYNOPSIS
    Repara el sistema de archivos de la partición TITAN-USB (solo esa) con chkdsk /f,
    para poder borrar carpetas dañadas que Windows ya no puede leer, y después borra lo
    que quede en Casos\ y las carpetas found.NNN que chkdsk cree.
    NO toca TITAN-BOOT ni TITAN-TOOLS. Requiere administrador. Pide escribir REPARAR.
#>
$ErrorActionPreference = 'Stop'
$raiz = $null
foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
    if (-not $d.IsReady) { continue }
    $r = $d.RootDirectory.FullName
    if ($d.VolumeLabel -eq 'TITAN-USB' -and (Test-Path -LiteralPath (Join-Path $r 'RESPALDO.marker'))) { $raiz = $r; break }
}
if (-not $raiz) { Write-Host 'No se encontró la partición TITAN-USB (con RESPALDO.marker). Conecte la USB TITAN.' -ForegroundColor Red; exit 1 }
$letra = $raiz.Substring(0, 2)
$casos = Join-Path $raiz 'Casos'

Write-Host ''
Write-Host ('Partición de respaldos de TITAN: {0}' -f $letra) -ForegroundColor Cyan
Write-Host 'Se hará:' -ForegroundColor Yellow
Write-Host ('  1. chkdsk {0} /f /x  (repara SOLO esta partición; la desmonta un momento)' -f $letra)
Write-Host ('  2. Borrar todo lo que quede dentro de {0}' -f $casos)
Write-Host ('  3. Borrar las carpetas found.NNN que cree chkdsk en {0}' -f $raiz)
Write-Host 'NO se tocan TITAN-BOOT ni TITAN-TOOLS, ni LEEME.txt, RESPALDO.marker o la carpeta Entrada.' -ForegroundColor Green
Write-Host ''
$resp = ([string](Read-Host 'Escriba REPARAR para confirmar (cualquier otra cosa cancela)')).Trim().ToUpperInvariant()
if ($resp -ne 'REPARAR') { Write-Host 'Cancelado. No se hizo nada.' -ForegroundColor Yellow; exit 0 }

Write-Host ''
Write-Host ('>>> chkdsk {0} /f /x' -f $letra) -ForegroundColor Cyan
$eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& (Join-Path $env:WINDIR 'System32\chkdsk.exe') $letra /f /x
$codigo = $LASTEXITCODE
$ErrorActionPreference = $eap
Write-Host ('chkdsk terminó con código {0}' -f $codigo)
Start-Sleep -Seconds 3

$borrar = @()
$borrar += @(Get-ChildItem -LiteralPath $casos -Force -ErrorAction SilentlyContinue)
$borrar += @(Get-ChildItem -LiteralPath $raiz -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^found\.\d{3}$' })
foreach ($b in $borrar) {
    $ErrorActionPreference = 'Continue'
    & cmd.exe /d /c ('rd /s /q "\\?\{0}"' -f $b.FullName) 2>&1 | Out-Null
    $ErrorActionPreference = $eap
    if (Test-Path -LiteralPath $b.FullName) { Write-Host ('  NO se pudo borrar: {0}' -f $b.FullName) -ForegroundColor Red }
    else { Write-Host ('  Borrado: {0}' -f $b.FullName) -ForegroundColor Green }
}

Write-Host ''
$quedan = @(Get-ChildItem -LiteralPath $casos -Force -ErrorAction SilentlyContinue)
$found = @(Get-ChildItem -LiteralPath $raiz -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^found\.\d{3}$' })
Write-Host 'Contenido de la partición de respaldos ahora:' -ForegroundColor Cyan
Get-ChildItem -LiteralPath $raiz -Force -ErrorAction SilentlyContinue | ForEach-Object { Write-Host ('  {0}' -f $_.Name) }
if ($quedan.Count -eq 0 -and $found.Count -eq 0) {
    Write-Host ''
    Write-Host 'LISTO: Casos quedó vacía y no quedan restos del equipo analizado.' -ForegroundColor Green
    exit 0
}
Write-Host 'Todavía quedan restos: revise los mensajes de arriba y vuelva a intentarlo.' -ForegroundColor Red
exit 1
