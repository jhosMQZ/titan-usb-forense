<#
.SYNOPSIS
    Comprueba, en un PC sano, que cada archivo de un respaldo de TITAN es idéntico al
    original: compara el SHA-256 de cada copia con el inventario que TITAN hizo del disco
    de origen (Datos\inventario_sha256.csv). SOLO LEE la USB. No abre ni ejecuta archivos.
    Resultado en la carpeta del kit: verificacion_respaldo_<caso>.csv y .txt
#>
param([string]$Caso = '')
$ErrorActionPreference = 'Stop'
$aqui = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$repo = Split-Path -Path $aqui -Parent

if (-not $Caso) {
    # La unidad RESPALDO de TITAN se reconoce por su marcador; se toma el caso más reciente con inventario
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        if (-not $d.IsReady) { continue }
        $raiz = $d.RootDirectory.FullName
        if (-not (Test-Path -LiteralPath (Join-Path $raiz 'RESPALDO.marker'))) { continue }
        $c = Get-ChildItem -LiteralPath (Join-Path $raiz 'Casos') -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'Datos\inventario_sha256.csv') } |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($c) { $Caso = $c.FullName; break }
    }
}
if (-not $Caso -or -not (Test-Path -LiteralPath (Join-Path $Caso 'Datos\inventario_sha256.csv'))) {
    Write-Host 'No se encontró un caso de TITAN con inventario. Conecte la USB TITAN.' -ForegroundColor Red
    exit 1
}
$nombre = Split-Path -Path $Caso -Leaf
Write-Host ('Caso: {0}' -f $Caso) -ForegroundColor Cyan

$enCuarentena = @{}
$csvCuar = Join-Path $Caso 'Datos\cuarentena.csv'
if (Test-Path -LiteralPath $csvCuar) {
    foreach ($q in (Import-Csv -LiteralPath $csvCuar -Delimiter ';' -Encoding UTF8)) { $enCuarentena[[string]$q.RutaOriginal] = $true }
}

function Get-Sha256Largo {
    param([string]$Ruta)
    $fs = [System.IO.File]::Open(('\\?\' + $Ruta), [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { return ([System.BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '') } finally { $sha.Dispose() }
    } finally { $fs.Dispose() }
}
$script:FF1M = New-Object byte[] 1048576
for ($k = 0; $k -lt $script:FF1M.Length; $k++) { $script:FF1M[$k] = 255 }
function Test-TodoFF {
    # ¿La copia es solo bytes 0xFF? (datos que nunca llegaron a la memoria)
    param([string]$Ruta)
    $fs = [System.IO.File]::Open(('\\?\' + $Ruta), [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $buf = New-Object byte[] 1048576
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
            $trozo = $buf
            if ($n -lt $buf.Length) { $trozo = New-Object byte[] $n; [Array]::Copy($buf, $trozo, $n) }
            $ff = $script:FF1M
            if ($n -lt $ff.Length) { $ff = New-Object byte[] $n; [Array]::Copy($script:FF1M, $ff, $n) }
            if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$trozo, [byte[]]$ff)) { return $false }
        }
        return $true
    } finally { $fs.Dispose() }
}

$inv = @(Import-Csv -LiteralPath (Join-Path $Caso 'Datos\inventario_sha256.csv') -Delimiter ';' -Encoding UTF8)
$res = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($x in $inv) {
    $i++
    if ($i % 50 -eq 0) { Write-Progress -Activity 'Verificando el respaldo' -Status ('{0} de {1}' -f $i, $inv.Count) -PercentComplete ($i * 100 / $inv.Count) }
    $orig = [string]$x.Ruta
    $m = [regex]::Match($orig, '(?i)^[A-Z]:\\Users\\(.+)$')
    $copia = ''
    if ($m.Success) { $copia = Join-Path $Caso ('Respaldo\' + $m.Groups[1].Value) }
    $estado = ''
    if ($enCuarentena.ContainsKey($orig)) { $estado = 'EN_CUARENTENA' }
    elseif (-not $copia) { $estado = 'FUERA_DE_USERS (revisar a mano)' }
    elseif (-not [System.IO.File]::Exists('\\?\' + $copia)) { $estado = 'NO_COPIADO' }
    else {
        try {
            $h = Get-Sha256Largo $copia
            if ($h -eq [string]$x.SHA256) { $estado = 'IDENTICO' }
            elseif (Test-TodoFF $copia) { $estado = 'VACIO (solo 0xFF)' }
            else { $estado = 'DISTINTO' }
        } catch { $estado = 'ILEGIBLE: ' + $_.Exception.Message }
    }
    $res.Add([pscustomobject]@{ Estado = $estado; Tamano = [int64]$x.Tamano; Original = $orig; Copia = $copia })
}
Write-Progress -Activity 'Verificando el respaldo' -Completed

$csv = Join-Path $repo ('verificacion_respaldo_{0}.csv' -f $nombre)
$res | Export-Csv -LiteralPath $csv -Delimiter ';' -NoTypeInformation -Encoding UTF8
$lineas = [System.Collections.Generic.List[string]]::new()
$lineas.Add(('Caso: {0}' -f $Caso))
$lineas.Add(('Archivos en el inventario: {0}' -f $res.Count))
foreach ($g in ($res | Group-Object { ($_.Estado -split ':')[0] } | Sort-Object Count -Descending)) {
    $mb = [math]::Round((($g.Group | Measure-Object Tamano -Sum).Sum) / 1MB, 1)
    $lineas.Add(('  {0,-34} {1,6} archivos  {2,10} MB' -f $g.Name, $g.Count, $mb))
}
$txt = Join-Path $repo ('verificacion_respaldo_{0}.txt' -f $nombre)
[System.IO.File]::WriteAllLines($txt, [string[]]$lineas, (New-Object System.Text.UTF8Encoding($true)))
$lineas | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host ('Detalle: {0}' -f $csv) -ForegroundColor Green
