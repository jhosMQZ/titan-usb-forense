#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Descarga/actualiza las firmas de ClamAV en el USB forense. Ejecútelo en el
    PC técnico SANO, con Internet, ANTES DE CADA USO del USB.

.DESCRIPTION
    - Primero verifica TODO el USB (Verificar-USB) contra la referencia de este
      PC: si algo fue alterado, NO ejecuta nada del USB.
    - Descarga bases COMPLETAS .cvd (firmadas por Cisco Talos).
    - Verifica la firma digital de cada .cvd con sigtool.
    - Guarda un resumen en ClamAV\database\firmas_info.txt.
    Nota: el CDN de ClamAV limita descargas muy seguidas; si responde
    "cool-down" o error 429, espere unas horas.
#>
param(
    [string]$Trabajo = 'C:\WinPE_USBForense'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Manifiesto.ps1')

Write-Paso 'Verificando el USB antes de ejecutar sus herramientas en este PC'
$v = Invoke-VerificacionUsb -Trabajo $Trabajo -SinFirmas
if (-not $v.Ok) {
    $v.Problemas | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw 'El USB no coincide con la referencia de este PC. NO se ejecuta ClamAV. Reconstrúyalo con Crear-USB.ps1.'
}
Write-Host 'USB verificado.' -ForegroundColor Green
$H = $v.Usb.H
$clam = "$H\ClamAV"
$db = "$clam\database"
Write-Paso ("Actualizando firmas en {0}" -f $clam)

New-Item -ItemType Directory -Path $db -Force | Out-Null
# Quitar bases incrementales o sueltas (sin firma verificable) de usos anteriores
foreach ($f in @(Get-ChildItem -LiteralPath $db -File -ErrorAction SilentlyContinue | Where-Object { @('.cvd', '.sign', '.dat', '.txt') -notcontains $_.Extension.ToLowerInvariant() })) {
    Remove-Item -LiteralPath $f.FullName -Force
}

$freshclam = "$clam\freshclam.exe"
$conf = "$clam\freshclam.conf"
$eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$salida = & $freshclam ('--config-file=' + $conf) ('--datadir=' + $db) 2>&1 | ForEach-Object { [string]$_ }
$codigo = $LASTEXITCODE
$ErrorActionPreference = $eap
$salida | ForEach-Object { Write-Host "  $_" }
# 0 = actualizado, 1 = ya estaba al día
if ($codigo -ne 0 -and $codigo -ne 1) { throw "freshclam terminó con código $codigo." }
if (($salida -join "`n") -match 'OUTDATED') {
    Write-Host 'AVISO: la versión de ClamAV del USB está desactualizada. Descargue la última y reconstruya el USB.' -ForegroundColor Yellow
}

# Verificación de firma digital
$sigtool = "$clam\sigtool.exe"
$info = New-Object System.Collections.Generic.List[string]
$info.Add(('Actualizado: {0} en el equipo {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $env:COMPUTERNAME))
$todoOk = $true
foreach ($n in @('main.cvd', 'daily.cvd', 'bytecode.cvd')) {
    $ruta = Join-Path $db $n
    if (-not (Test-Path -LiteralPath $ruta)) { Write-Host "FALTA $n" -ForegroundColor Red; $todoOk = $false; continue }
    $ErrorActionPreference = 'Continue'
    $out = (& $sigtool ('--info=' + $ruta) 2>&1 | ForEach-Object { [string]$_ }) -join "`n"
    $ErrorActionPreference = $eap
    $ok = $out -match 'Verification OK'
    if (-not $ok) { $todoOk = $false }
    $ver = ''; $fecha = ''
    $m = [regex]::Match($out, '(?im)^Version:\s*(\d+)'); if ($m.Success) { $ver = $m.Groups[1].Value }
    $m = [regex]::Match($out, '(?im)^Build time:\s*(.+)$'); if ($m.Success) { $fecha = $m.Groups[1].Value.Trim() }
    $linea = '{0,-13} versión {1,-7} generada {2}  firma: {3}' -f $n, $ver, $fecha, $(if ($ok) { 'VÁLIDA' } else { 'NO VÁLIDA' })
    $info.Add($linea)
    if ($ok) { Write-Host "  $linea" -ForegroundColor Green } else { Write-Host "  $linea" -ForegroundColor Red }
}
[System.IO.File]::WriteAllLines("$db\firmas_info.txt", [string[]]$info, (New-Object System.Text.UTF8Encoding($true)))
if (-not $todoOk) { throw 'Alguna base de firmas falta o no tiene firma válida.' }
Write-Host 'Firmas de ClamAV actualizadas y verificadas.' -ForegroundColor Green
