<#
.SYNOPSIS
    Descifra UN archivo de la cuarentena (.cuar) para analizarlo o enviarlo a
    un laboratorio (p. ej. VirusTotal) o para recuperarlo si fue un falso
    positivo.

.DESCRIPTION
    ¡PELIGRO! El resultado es el archivo original, posiblemente malicioso.
    Hágalo SOLO dentro de una máquina virtual aislada y sin carpetas
    compartidas. El archivo se guarda con la extensión adicional ".peligroso"
    para que no se abra con doble clic. Compruebe que el SHA-256 coincide con
    el de cuarentena.csv antes de confiar en él.

.EXAMPLE
    .\Restaurar-Cuarentena.ps1 -Archivo E:\Casos\20261030_141500\Cuarentena\Q0001_ABCD1234ABCD1234.cuar -Destino C:\Analisis
#>
param(
    [Parameter(Mandatory = $true)][string]$Archivo,
    [Parameter(Mandatory = $true)][string]$Destino
)
$ErrorActionPreference = 'Stop'
$clave = 'infected'

if (-not (Test-Path -LiteralPath $Archivo)) { throw "No existe $Archivo" }
$meta = $null
$json = [System.IO.Path]::ChangeExtension($Archivo, '.json')
if (Test-Path -LiteralPath $json) { $meta = Get-Content -LiteralPath $json -Raw -Encoding UTF8 | ConvertFrom-Json }
$id = [System.IO.Path]::GetFileNameWithoutExtension($Archivo)
$nombre = ''
if ($meta -and $meta.RutaOriginal) { $nombre = [System.IO.Path]::GetFileName([string]$meta.RutaOriginal) }
# El nombre viene del equipo analizado: se limpia (sin controles, sin caracteres
# de inversión RLO, sin reservados) y se antepone el Id para evitar sorpresas.
$nombre = [regex]::Replace($nombre, '[\x00-\x1F\x7F\u202A-\u202E\u2066-\u2069\\/:*?"<>|]', '_').Trim(' ', '.')
if ($nombre.Length -gt 80) { $nombre = $nombre.Substring(0, 80) }
$nombre = '{0}_{1}' -f $id, $nombre

Write-Host 'Va a recuperar un archivo considerado PELIGROSO.' -ForegroundColor Red
if ($meta) { Write-Host ('Origen: {0}' -f ([string]$meta.RutaOriginal -replace '[\x00-\x1F\u202A-\u202E\u2066-\u2069]', '?')); Write-Host ('Motivos: {0}' -f (@($meta.Motivos) -join ' | ')) }
# Recomendado solo dentro de una máquina virtual aislada
$modelo = ''
try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem; $modelo = ('{0} {1}' -f $cs.Manufacturer, $cs.Model) } catch { }
if ($modelo -notmatch '(?i)virtual|vmware|virtualbox|qemu|kvm|xen|hyper-v|parallels') {
    Write-Host ("Este equipo NO parece una máquina virtual ({0})." -f $modelo) -ForegroundColor Red
    if ((Read-Host 'Escriba CONTINUAR FUERA DE UNA VM para seguir') -ne 'CONTINUAR FUERA DE UNA VM') { throw 'Cancelado.' }
}
if ((Read-Host 'Escriba ENTIENDO EL RIESGO para continuar') -ne 'ENTIENDO EL RIESGO') { throw 'Cancelado.' }

New-Item -ItemType Directory -Path $Destino -Force | Out-Null
$salidaRuta = Join-Path $Destino ($nombre + '.peligroso')
$entrada = [System.IO.File]::OpenRead($Archivo)
try {
    $magia = New-Object byte[] 5
    [void]$entrada.Read($magia, 0, 5)
    $tipo = [System.Text.Encoding]::ASCII.GetString($magia)
    $salida = [System.IO.File]::Open($salidaRuta, [System.IO.FileMode]::CreateNew)
    try {
        if ($tipo -eq 'CUAR1') {
            $sal = New-Object byte[] 16; [void]$entrada.Read($sal, 0, 16)
            $iv = New-Object byte[] 16; [void]$entrada.Read($iv, 0, 16)
            $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $clave, $sal, 10000
            $aes = New-Object System.Security.Cryptography.AesManaged
            $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
            $aes.Key = $kdf.GetBytes(32); $aes.IV = $iv
            $descifrador = $aes.CreateDecryptor()
            $modo = [System.Security.Cryptography.CryptoStreamMode]::Read
            $cs = New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($entrada, $descifrador, $modo)
            $cs.CopyTo($salida, 1048576)
            $cs.Dispose(); $aes.Dispose(); $kdf.Dispose()
        } elseif ($tipo -eq 'CUARX') {
            $buf = New-Object byte[] 1048576
            while (($n = $entrada.Read($buf, 0, $buf.Length)) -gt 0) {
                for ($i = 0; $i -lt $n; $i++) { $buf[$i] = $buf[$i] -bxor 0x5A }
                $salida.Write($buf, 0, $n)
            }
        } else { throw 'No es un archivo de cuarentena válido.' }
    } finally { $salida.Dispose() }
} finally { $entrada.Dispose() }

# Marca de la Web (zona Internet): SmartScreen y Office lo tratarán como descargado
Set-Content -LiteralPath $salidaRuta -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3`r`n" -Encoding Ascii
$hash = (Get-FileHash -LiteralPath $salidaRuta -Algorithm SHA256).Hash
Write-Host ('Recuperado en: {0}' -f $salidaRuta) -ForegroundColor Yellow
Write-Host ('SHA-256: {0}' -f $hash)
if ($meta -and $meta.SHA256) {
    if ($hash -eq [string]$meta.SHA256) { Write-Host 'Coincide con el hash registrado en cuarentena.' -ForegroundColor Green }
    else { Write-Host 'NO coincide con el hash registrado: el archivo de cuarentena está dañado.' -ForegroundColor Red }
}
