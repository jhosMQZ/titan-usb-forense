<#
.SYNOPSIS
    Revisa la sintaxis de TODOS los scripts del kit con el analizador oficial
    de PowerShell de este Windows (no ejecuta ninguno). Solo lectura.
    Código de salida: 0 = sin errores, 1 = hay errores (ver sintaxis_errores.txt).
#>
param([string]$Kit = '')
$ErrorActionPreference = 'Stop'
if (-not $Kit) { $Kit = Split-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Path -Parent) -Parent }
$salida = Join-Path $Kit 'sintaxis_errores.txt'
$lineas = New-Object System.Collections.Generic.List[string]
$archivos = @(Get-ChildItem -LiteralPath $Kit -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notlike '*\Descargas\*' })
$n = 0
foreach ($f in $archivos) {
    $tokens = $null; $errores = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errores)
    foreach ($e in @($errores)) {
        $n++
        $lineas.Add(('{0}:{1}:{2}  {3}' -f $f.FullName.Substring($Kit.Length).TrimStart('\'), $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message))
    }
}
$lineas.Insert(0, ('Revisados {0} scripts con PowerShell {1}. Errores: {2}' -f $archivos.Count, $PSVersionTable.PSVersion, $n))
[System.IO.File]::WriteAllLines($salida, [string[]]$lineas, (New-Object System.Text.UTF8Encoding($true)))
foreach ($l in $lineas) { if ($n -gt 0) { Write-Host $l -ForegroundColor Red } else { Write-Host $l -ForegroundColor Green } }
if ($n -gt 0) { exit 1 } else { exit 0 }
