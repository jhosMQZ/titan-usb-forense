#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verificación FUERTE del USB forense desde el PC técnico sano.
    Ejecútela ANTES de cada uso y DESPUÉS de volver de un equipo analizado.

.DESCRIPTION
    La huella que muestra el USB al arrancar la calcula código que está en el
    propio USB: sirve para detectar errores, pero alguien que modificara a la
    vez herramientas y boot.wim podría falsearla. Esta verificación usa como
    referencia los hashes guardados EN ESTE PC al crear el USB, así que no
    depende de nada que esté en el USB:
      - Partición WINPE completa (boot.wim con el ancla, gestor de arranque, BCD).
      - Partición HERRAMIENTAS (cada archivo; faltantes y sobrantes).
      - Firmas digitales de las bases de ClamAV.
      - Restos peligrosos (autorun.inf, temporales de análisis interrumpidos).
    Código de salida: 0 = correcto, 1 = problemas.
#>
param(
    [string]$Trabajo = 'C:\WinPE_USBForense',
    [switch]$LimpiarTemporales
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Manifiesto.ps1')

Write-Paso 'Verificando el USB forense contra la referencia guardada en este PC'
$r = Invoke-VerificacionUsb -Trabajo $Trabajo
Write-Host ('USB: disco #{0}, firma {1}  |  WINPE={2}  HERRAMIENTAS={3}  RESPALDO={4}' -f $r.Usb.Disco, $r.Usb.Id, $r.Usb.P, $r.Usb.H, $r.Usb.R)
$huella = Get-HuellaManifiesto (Join-Path $Trabajo 'manifest.sha256')
Write-Host ("Huella esperada al arrancar: {0}" -f $huella) -ForegroundColor Cyan

foreach ($a in $r.Avisos) { Write-Host "  AVISO: $a" -ForegroundColor Yellow }
if ($LimpiarTemporales) {
    foreach ($t in @(Get-ChildItem -LiteralPath "$($r.Usb.R)\Casos" -Directory -ErrorAction SilentlyContinue)) {
        $tw = Join-Path $t.FullName 'Trabajo'
        if (Test-Path -LiteralPath $tw) { Remove-Item -LiteralPath $tw -Recurse -Force; Write-Host "  Eliminado: $tw" -ForegroundColor Green }
    }
}
if ($r.Ok) {
    Write-Host 'USB VERIFICADO: coincide exactamente con lo que se creó en este PC.' -ForegroundColor Green
    exit 0
}
Write-Host 'USB CON PROBLEMAS:' -ForegroundColor Red
$r.Problemas | Select-Object -First 60 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
Write-Host 'No lo use. Si usted no cambió nada, reconstrúyalo con Crear-USB.ps1 (si solo cambió scripts, use Actualizar-Ancla.ps1).' -ForegroundColor Red
exit 1
