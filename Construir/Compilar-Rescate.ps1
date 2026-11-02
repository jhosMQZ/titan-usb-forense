<#
.SYNOPSIS
    Compila el motor de TITAN BLACKBOX (Herramientas\Blackbox\TitanRescate.cs)
    con el compilador de C# que ya trae Windows (.NET Framework 4, csc.exe).
    No descarga nada. Solo escribe Herramientas\Blackbox\TitanRescate.exe.
    Código de salida: 0 = compilado y probado, 1 = error.
#>
param([string]$Kit = '', [switch]$SiHaceFalta)
$ErrorActionPreference = 'Continue'   # csc y el motor escriben en la consola; se comprueba cada código de salida
if (-not $Kit) { $Kit = Split-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Path -Parent) -Parent }
$fuente = Join-Path $Kit 'Herramientas\Blackbox\TitanRescate.cs'
$exe = Join-Path $Kit 'Herramientas\Blackbox\TitanRescate.exe'
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { Write-Host "No se encontró $csc (.NET Framework 4)." -ForegroundColor Red; exit 1 }
if (-not (Test-Path -LiteralPath $fuente)) { Write-Host "No existe $fuente" -ForegroundColor Red; exit 1 }
if ($SiHaceFalta -and (Test-Path -LiteralPath $exe) -and (Get-Item -LiteralPath $exe).LastWriteTimeUtc -ge (Get-Item -LiteralPath $fuente).LastWriteTimeUtc) {
    Write-Host 'Motor BLACKBOX al día (no hace falta compilar).' -ForegroundColor Green
    exit 0
}
$tmp = Join-Path (Split-Path -Path $exe -Parent) 'TitanRescate.nuevo.exe'   # debe terminar en .exe: si no, PowerShell lo trata como documento y no lo ejecuta
if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
$salida = & $csc /nologo /optimize+ /target:exe /platform:x64 /utf8output ('/out:' + $tmp) $fuente 2>&1 | ForEach-Object { [string]$_ }
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tmp)) {
    $salida | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    Write-Host 'La compilación del motor FALLÓ.' -ForegroundColor Red
    exit 1
}
$v = & $tmp version 2>&1 | ForEach-Object { [string]$_ } | Where-Object { $_.StartsWith('TITAN_RESULTADO ') } | Select-Object -First 1
if (-not $v -or $v -notmatch '"estado":"OK"' -or $v -notmatch '"x64":true') {
    Write-Host ('El motor compilado no responde bien: {0}' -f $v) -ForegroundColor Red
    Remove-Item -LiteralPath $tmp -Force
    exit 1
}
Move-Item -LiteralPath $tmp -Destination $exe -Force
$h = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
Write-Host ('Motor compilado: {0}' -f $exe) -ForegroundColor Green
Write-Host ('  SHA-256 {0}' -f $h)
Write-Host ('  {0}' -f $v.Substring(16))
exit 0
