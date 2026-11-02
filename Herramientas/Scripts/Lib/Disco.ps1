<#
    Disco.ps1 - Detección de discos, montaje en SOLO LECTURA, BitLocker,
    revisión del sistema de archivos (chkdsk sin reparar) y salud SMART.
#>

# ---------------------------------------------------------------------------
# Discos vía DISKPART. En algunos WinPE (visto en un portátil con NVMe) los
# cmdlets de almacenamiento (Get-Disk, Get-Partition) devuelven listas vacías;
# diskpart funciona siempre, así que es la fuente principal.
# ---------------------------------------------------------------------------
function Invoke-Diskpart {
    param([string[]]$Comandos)
    $archivo = Join-Path $env:TEMP ('dp_{0}.txt' -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllLines($archivo, [string[]]($Comandos + @('exit')), [System.Text.Encoding]::ASCII)
    $salida = @()
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $salida = @(& (Join-Path $env:SystemRoot 'System32\diskpart.exe') /s $archivo 2>&1 | ForEach-Object { [string]$_ })
    } finally {
        $ErrorActionPreference = $eap
        Remove-Item -LiteralPath $archivo -Force -ErrorAction SilentlyContinue
    }
    return , $salida
}

function ConvertFrom-TamanoDiskpart {
    # "476 GB" -> bytes aproximados
    param([string]$Texto)
    $m = [regex]::Match([string]$Texto, '(\d+)\s*(B|KB|MB|GB|TB)\b', 'IgnoreCase')
    if (-not $m.Success) { return [int64]0 }
    $n = [int64]$m.Groups[1].Value
    switch ($m.Groups[2].Value.ToUpperInvariant()) {
        'KB' { return $n * 1KB }
        'MB' { return $n * 1MB }
        'GB' { return $n * 1GB }
        'TB' { return $n * 1TB }
    }
    return $n
}

function Get-ListaDiscosDp {
    $res = @()
    foreach ($l in (Invoke-Diskpart @('list disk'))) {
        $m = [regex]::Match($l, '^\s*\*?\s*(?:Disk|Disco)\s+(\d+)\s+(.+?)\s{2,}(\d+\s*[KMGT]?B)\b')
        if ($m.Success) {
            $res += [pscustomobject]@{ Number = [int]$m.Groups[1].Value; Estado = $m.Groups[2].Value.Trim(); Tamano = $m.Groups[3].Value }
        }
    }
    return $res
}

function Get-DetalleDiscoConTamanoDp {
    # Como Get-DetalleDiscoDp, pero con el tamaño tomado de 'list disk' ("detail disk" no lo da)
    param([int]$Numero)
    $tam = ''
    foreach ($x in @(Get-ListaDiscosDp)) { if ($x.Number -eq $Numero) { $tam = $x.Tamano } }
    return (Get-DetalleDiscoDp -Numero $Numero -TamanoTexto $tam)
}

function Get-ColumnaDp {
    # Texto de una columna de la salida de diskpart (por posición)
    param([string]$Linea, [int]$Inicio, [int]$Largo)
    if ($Inicio -lt 0 -or $Inicio -ge $Linea.Length) { return '' }
    $fin = [Math]::Min($Linea.Length, $Inicio + $Largo)
    return $Linea.Substring($Inicio, $fin - $Inicio).Trim()
}

function Get-DetalleDiscoDp {
    <#
      Devuelve: Number, FriendlyName, BusType, Id (firma MBR de 8 hex o {GUID}),
      PartitionStyle, Size, IsOffline, IsReadOnly, IsBoot, Volumenes (Num, Letra,
      Fs, Tamano, Info).
    #>
    param([int]$Numero, [string]$TamanoTexto = '')
    $o = @()
    for ($intento = 1; $intento -le 3; $intento++) {
        # Si el servicio de discos está ocupado, diskpart devuelve una salida incompleta: se reintenta
        $o = Invoke-Diskpart @("select disk $Numero", 'detail disk', 'uniqueid disk')
        if (@($o | Where-Object { $_ -match '^\s*(?:Disk ID|Id\.? de disco|Id\.? del disco)\s*:' }).Count -gt 0) { break }
        if ($intento -lt 3) { Start-Sleep -Seconds 2 }
    }
    $d = [ordered]@{
        Number = $Numero; FriendlyName = ''; BusType = ''; Id = ''; PartitionStyle = ''
        Size = (ConvertFrom-TamanoDiskpart $TamanoTexto); IsOffline = $false; IsReadOnly = $false; AtributoSoloLectura = $false; IsBoot = $false
        Volumenes = @()
    }
    $iId = -1
    for ($i = 0; $i -lt $o.Count; $i++) {
        $l = $o[$i]
        if ($iId -lt 0 -and $l -match '^\s*(?:Disk ID|Id\.? de disco|Id\.? del disco)\s*:\s*(\S+)') { $iId = $i; $d.Id = $Matches[1].Trim('{', '}').ToUpperInvariant(); continue }
        if ($l -match '^\s*(?:Type|Tipo)\s*:\s*(.+?)\s*$') { if (-not $d.BusType) { $d.BusType = $Matches[1] }; continue }
        if ($l -match '^\s*(?:Status|Estado)\s*:\s*(.+?)\s*$') { if ($Matches[1] -match '(?i)offline|sin conexi|no conectado|fuera de l') { $d.IsOffline = $true }; continue }
        if ($l -match '^\s*(?:Current Read-only State|Estado actual de solo lectura|Estado de solo lectura actual)\s*:\s*(\S+)') { $d.IsReadOnly = ($Matches[1] -match '(?i)^(yes|s)'); continue }
        if ($l -match '^\s*(?:Read-only|Solo lectura)\s*:\s*(\S+)') { $d.AtributoSoloLectura = ($Matches[1] -match '(?i)^(yes|s)'); continue }
        if ($l -match '^\s*(?:Boot Disk|Disco de arranque)\s*:\s*(\S+)') { $d.IsBoot = ($Matches[1] -match '(?i)^(yes|s)'); continue }
    }
    if ($iId -gt 0) {
        for ($j = $iId - 1; $j -ge 0; $j--) {
            $t = $o[$j].Trim()
            if ($t -and $t -notmatch '(?i)(selected|seleccionado|^Microsoft DiskPart|^DISKPART>|Copyright|^On computer|^En el equipo|^Leaving|^Saliendo)') { $d.FriendlyName = $t; break }
        }
    }
    if ($d.Id -match '^[0-9A-F]{8}$') { $d.PartitionStyle = 'MBR' } elseif ($d.Id) { $d.PartitionStyle = 'GPT' }
    # Volúmenes: columnas según la cabecera ("Ltr", "Fs", "Size"/"Tamaño", "Info")
    $cab = $null
    foreach ($l in $o) { if ($l -match 'Ltr' -and $l -match '\bFs\b') { $cab = $l; break } }
    if ($cab) {
        $pL = $cab.IndexOf('Ltr'); $pF = [regex]::Match($cab, '\bFs\b').Index
        $mT = [regex]::Match($cab, '(Size|Tamaño)'); $pI = $cab.IndexOf('Info')
        foreach ($l in $o) {
            $mv = [regex]::Match($l, '^\s*\*?\s*(?:Volume|Volumen)\s+(\d+)')
            if (-not $mv.Success) { continue }
            $letra = Get-ColumnaDp $l $pL 3
            if ($letra -notmatch '^[A-Za-z]$') { $letra = '' }
            $info = ''
            if ($pI -ge 0) { $info = Get-ColumnaDp $l $pI 40 }
            $tam = ''
            if ($mT.Success) { $tam = Get-ColumnaDp $l ($mT.Index - 2) 10 }
            $d.Volumenes += [pscustomobject]@{
                Num = [int]$mv.Groups[1].Value; Letra = $letra.ToUpperInvariant(); Fs = (Get-ColumnaDp $l $pF 6)
                Tamano = (ConvertFrom-TamanoDiskpart $tam); Info = $info
            }
        }
    }
    return [pscustomobject]$d
}

function Get-DiscosDp {
    $res = @()
    foreach ($x in @(Get-ListaDiscosDp)) { $res += Get-DetalleDiscoDp -Numero $x.Number -TamanoTexto $x.Tamano }
    return $res
}

function Get-NumeroDiscoDeVolumenDp {
    # Busca la letra en los volúmenes de cada disco ("detail disk", el mismo
    # método que ya funciona al arrancar). Respaldo: "detail volume".
    param([string]$Letra)
    $l1 = $Letra.Substring(0, 1).ToUpperInvariant()
    foreach ($x in @(Get-ListaDiscosDp)) {
        foreach ($v in (Get-DetalleDiscoDp -Numero $x.Number).Volumenes) {
            if ($v.Letra -eq $l1) { return [int]$x.Number }
        }
    }
    $o = Invoke-Diskpart @(('select volume {0}' -f $l1), 'detail volume')
    foreach ($l in $o) {
        $m = [regex]::Match($l, '^\s*\*?\s*(?:Disk|Disco)\s+(\d+)\s')
        if ($m.Success) { return [int]$m.Groups[1].Value }
    }
    return -1
}

function Add-LetrasVolumenesDp {
    # Asigna letra a los volúmenes de datos del disco que no la tengan.
    # (Solo registra el punto de montaje en WinPE; no escribe en el disco.)
    param([int]$Numero)
    $det = Get-DetalleDiscoDp -Numero $Numero
    foreach ($v in $det.Volumenes) {
        if ($v.Letra) { continue }
        if ($v.Info -match '(?i)(hidden|oculto|system|sistema)') { continue }
        if ($v.Tamano -gt 0 -and $v.Tamano -lt 512MB) { continue }
        # Un volumen cifrado con BitLocker (bloqueado) aparece sin sistema de
        # archivos (o RAW): también necesita letra para poder desbloquearlo.
        if ($v.Fs -notmatch '(?i)^(NTFS|FAT32|FAT|exFAT|ReFS)$' -and $v.Tamano -lt 2GB) { continue }
        $ra = Invoke-Diskpart @(('select volume {0}' -f $v.Num), 'assign noerr')
        Write-Log ('assign volumen {0} ({1}, {2}): {3}' -f $v.Num, $v.Fs, (Format-Bytes $v.Tamano), (($ra | Where-Object { $_ -and $_ -notmatch '(?i)DiskPart|Copyright|computer|equipo' }) -join ' | ')) -SoloArchivo
    }
}

function Write-DiagnosticoDp {
    # Vuelca al registro la salida cruda de diskpart de un disco (para diagnóstico)
    param([int]$Numero, [string]$Motivo)
    try {
        Write-Log ('--- diskpart ({0}) ---' -f $Motivo) -SoloArchivo
        foreach ($l in (Invoke-Diskpart @("select disk $Numero", 'detail disk', 'list volume'))) { if ($l) { Write-Log ('  dp> ' + $l) -SoloArchivo } }
    } catch { Write-Log ('  diskpart no se pudo ejecutar: ' + $_.Exception.Message) -SoloArchivo }
}

function Get-NumeroDiscoDeLetra {
    param([string]$Letra)
    $n = Get-NumeroDiscoDeVolumenDp -Letra $Letra
    if ($n -lt 0) {
        # Diagnóstico: salida cruda de diskpart en el registro
        try {
            foreach ($l in (Invoke-Diskpart @('list disk', 'list volume'))) { Write-Log ('  diskpart> ' + $l) -SoloArchivo }
            Write-Log ('  TEMP={0}' -f $env:TEMP) -SoloArchivo
        } catch { Write-Log ('  diskpart no se pudo ejecutar: ' + $_.Exception.Message) -SoloArchivo }
        throw "No se pudo saber a qué disco pertenece $Letra (diskpart)."
    }
    return $n
}

function Get-LetrasDeDisco {
    # Letras de unidad (formato 'D:') de los volúmenes de un disco.
    param([int]$Numero)
    $letras = @()
    foreach ($v in (Get-DetalleDiscoDp -Numero $Numero).Volumenes) { if ($v.Letra) { $letras += ('{0}:' -f $v.Letra) } }
    return $letras
}

function Show-Discos {
    param([int]$NumeroUsb)
    $lista = @(Get-DiscosDp | Sort-Object Number)
    Write-Host ''
    Write-Host ('{0,-4} {1,-36} {2,-8} {3,10} {4,-8} {5,-10} {6}' -f 'N.', 'Modelo', 'Bus', 'Tamaño', 'Estilo', 'Estado', 'Nota')
    foreach ($d in $lista) {
        $nota = ''
        if ($d.Number -eq $NumeroUsb) { $nota = '<- USB DE TRABAJO (excluido)' }
        $estado = 'En línea'
        if ($d.IsOffline) { $estado = 'Fuera lín.' }
        if ($d.IsReadOnly) { $estado += ' RO' }
        $modelo = [string]$d.FriendlyName
        if ($modelo.Length -gt 35) { $modelo = $modelo.Substring(0, 35) }
        Write-Host ('{0,-4} {1,-36} {2,-8} {3,10} {4,-8} {5,-10} {6}' -f $d.Number, $modelo, $d.BusType, (Format-Bytes $d.Size), $d.PartitionStyle, $estado, $nota)
    }
    Write-Host ''
    return $lista
}

function Set-DiscoSoloLectura {
    <#
      Pone el disco en SOLO LECTURA a nivel de disco (todas sus particiones) con
      diskpart: fuera de línea -> atributo solo lectura -> en línea.
      El atributo vive en el registro de WinPE (en RAM): no se escribe en el
      disco analizado y desaparece al reiniciar.
    #>
    param([int]$Numero, [int]$NumeroUsb)
    if ($Numero -eq $NumeroUsb) { throw "Protección: el disco $Numero es el USB de trabajo; no se toca." }
    $antes = Get-DetalleDiscoDp -Numero $Numero
    # (En WinPE el disco "de arranque" es el USB, ya excluido arriba; si diskpart
    # marcara también el disco analizado, solo se anota: igual queda en solo lectura.)
    if ($antes.IsBoot) { Write-Log ("Aviso: diskpart marca el disco {0} como disco de arranque." -f $Numero) -SoloArchivo }
    # Cada paso en una llamada aparte y comprobando el estado: si un paso da error
    # (p. ej. "This disk is already offline" porque el arranque ya lo protegió),
    # diskpart abandona el resto del guion y el disco se quedaba sin poner en línea.
    $limpia = { param($o) (($o | Where-Object { $_ -and $_ -notmatch '(?i)DiskPart version|Copyright|On computer|En el equipo' }) -join ' | ') }
    if (-not $antes.IsOffline) {
        $r = Invoke-Diskpart @("select disk $Numero", 'offline disk noerr')
        Write-Log ('offline: ' + (& $limpia $r)) -SoloArchivo
    }
    # Con el disco fuera de línea, diskpart muestra el ATRIBUTO ("Read-only: Yes")
    # aunque el "estado actual" diga No: antes de ponerlo en línea se exige el atributo.
    $d0 = Get-DetalleDiscoDp -Numero $Numero
    if (-not ($d0.AtributoSoloLectura -or $d0.IsReadOnly)) {
        $r = Invoke-Diskpart @("select disk $Numero", 'attributes disk set readonly noerr')
        Write-Log ('readonly: ' + (& $limpia $r)) -SoloArchivo
        Start-Sleep -Seconds 2
        $d0 = Get-DetalleDiscoDp -Numero $Numero
    }
    Write-Log ('antes de ponerlo en línea: fuera de línea={0} atributo solo lectura={1} estado actual solo lectura={2}' -f $d0.IsOffline, $d0.AtributoSoloLectura, $d0.IsReadOnly) -SoloArchivo
    if (-not ($d0.AtributoSoloLectura -or $d0.IsReadOnly)) {
        Write-DiagnosticoDp -Numero $Numero -Motivo 'no se pudo poner solo lectura'
        throw "No se pudo confirmar el modo SOLO LECTURA del disco $Numero. Se detiene por seguridad."
    }
    # Solo con el atributo de solo lectura ya confirmado, se pone en línea
    $r = Invoke-Diskpart @("select disk $Numero", 'online disk noerr')
    Write-Log ('online: ' + (& $limpia $r)) -SoloArchivo
    Start-Sleep -Seconds 3
    if (-not (Test-DiscoSoloLectura -Numero $Numero)) {
        # No debería pasar; por seguridad se vuelve a desconectar y se detiene
        [void](Invoke-Diskpart @("select disk $Numero", 'offline disk noerr'))
        throw "El disco $Numero perdió el modo SOLO LECTURA al ponerlo en línea. Se desconectó y se detiene por seguridad."
    }
    # Al ponerlo en línea, Windows tarda unos segundos en presentar los volúmenes
    $det = $null
    for ($i = 1; $i -le 10; $i++) {
        $det = Get-DetalleDiscoDp -Numero $Numero
        if (@($det.Volumenes).Count -gt 0) { break }
        if ($det.IsOffline) { [void](Invoke-Diskpart @("select disk $Numero", 'online disk noerr')) }
        Start-Sleep -Seconds 3
    }
    Write-DiagnosticoDp -Numero $Numero -Motivo 'disco en línea y solo lectura'
    # Letras para los volúmenes de datos (Windows, datos) que no tengan
    Add-LetrasVolumenesDp -Numero $Numero
    Start-Sleep -Seconds 3
    return $true
}

function Test-DiscoSoloLectura {
    param([int]$Numero)
    try { return [bool](Get-DetalleDiscoDp -Numero $Numero).IsReadOnly } catch { return $false }
}

function Assert-SoloLectura {
    # Se llama al inicio de cada fase: si algo quitó el atributo, se detiene todo.
    param([int]$Numero)
    if (-not (Test-DiscoSoloLectura -Numero $Numero)) {
        throw "El disco #$Numero dejó de estar en SOLO LECTURA. Proceso detenido por seguridad."
    }
}

function Get-EstadoSecureBoot {
    try {
        $v = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction Stop
        if ([int]$v.UEFISecureBootEnabled -eq 1) { return 'ACTIVO' }
        return 'INACTIVO'
    } catch { return 'DESCONOCIDO (arranque heredado/BIOS o dato no disponible)' }
}

function Get-FirmaDiscoUsbEsperada {
    # Identificador único (firma MBR) del USB, sellado en X:\Ancla al crearlo
    $f = Join-Path $env:SystemDrive 'Ancla\usb-id.txt'
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    $t = ([System.IO.File]::ReadAllText($f)).Trim()
    if ($t -notmatch '^[0-9A-Fa-f]{8}$') { return $null }
    return [Convert]::ToUInt32($t, 16)
}

# ---------------------------------------------------------------------------
# BitLocker (requiere el componente WinPE-SecureStartup)
# ---------------------------------------------------------------------------
function Get-VolumenCifrado {
    param([string]$Letra)
    # WMI desactivado a propósito: en algunos WinPE (visto en un portátil de prueba) System.Management
    # provoca un AccessViolation que no se puede capturar y cierra PowerShell.
    # Todo BitLocker se hace con manage-bde.exe, que corre en un proceso aparte.
    return $null
}

function Get-EstadoBitLocker {
    param([string]$Letra)
    $v = Get-VolumenCifrado -Letra $Letra
    if ($null -eq $v) {
        # Sin WMI de BitLocker: se intenta con manage-bde (salida según idioma)
        $r = Invoke-Nativo 'manage-bde.exe' @('-status', $Letra)
        $t = $r.Salida -join "`n"
        if ($t -match '(?i)(Lock Status|Estado de bloqueo)\s*:\s*(Locked|Bloqueado)') { return 'Bloqueado' }
        if ($t -match '(?i)(Fully Decrypted|Totalmente descifrado|Completamente descifrado)') { return 'SinBitLocker' }
        if ($t -match '(?i)(not a valid BitLocker volume|no es un volumen( de)? BitLocker v)') { return 'SinBitLocker' }
        if ($t -match '(?i)(Lock Status|Estado de bloqueo)\s*:\s*(Unlocked|Desbloqueado)') { return 'Desbloqueado' }
        # manage-bde no supo decir: si la raíz no se puede leer, puede ser BitLocker bloqueado
        $legible = $false
        try { [void][System.IO.Directory]::GetFileSystemEntries($Letra + '\'); $legible = $true } catch { }
        if (-not $legible) { return 'Bloqueado' }
        return 'SinBitLocker'
    }
    try {
        $ls = $v.GetLockStatus()
        if ($ls.LockStatus -eq 1) { return 'Bloqueado' }
        $ps = $v.GetProtectionStatus()
        if ($ps.ProtectionStatus -eq 0) {
            $cs = $v.GetConversionStatus()
            if ($cs.ConversionStatus -eq 0) { return 'SinBitLocker' }
        }
        return 'Desbloqueado'
    } catch { return 'Desconocido' }
}

function Unlock-VolumenBitLocker {
    param([string]$Letra, [string]$ClaveRecuperacion)
    $v = Get-VolumenCifrado -Letra $Letra
    if ($v) {
        try {
            $r = $v.UnlockWithNumericalPassword($ClaveRecuperacion)
            if ($r.ReturnValue -eq 0) { return $true }
        } catch { }
    }
    $r2 = Invoke-Nativo 'manage-bde.exe' @('-unlock', $Letra, '-RecoveryPassword', $ClaveRecuperacion)
    return ((Get-EstadoBitLocker -Letra $Letra) -eq 'Desbloqueado')
}

function Invoke-DesbloqueoBitLocker {
    param([string[]]$Letras)
    foreach ($l in $Letras) {
        $estado = Get-EstadoBitLocker -Letra $l
        if ($estado -ne 'Bloqueado') { continue }
        Write-Log ("El volumen {0} está cifrado con BitLocker y BLOQUEADO (o no se puede leer)." -f $l) -Nivel AVISO
        Write-Host 'Obtenga la clave de recuperación (48 dígitos) en https://account.microsoft.com/devices/recoverykey desde OTRO equipo.' -ForegroundColor Yellow
        for ($i = 1; $i -le 3; $i++) {
            # La clave se escribe oculta: no aparece en pantalla ni en Registros\consola.txt
            $clave = ([string](Read-Secreto ("Clave de recuperación para {0}, 48 dígitos con guiones (Enter para omitir)" -f $l))).Trim()
            if ($clave -eq '') { Write-Log ("Volumen {0} omitido (sigue bloqueado)." -f $l) -Nivel AVISO; break }
            if ($clave -notmatch '^\d{6}(-\d{6}){7}$') { Write-Host 'Formato: 8 grupos de 6 dígitos separados por guiones.' -ForegroundColor Yellow; continue }
            $ok = Unlock-VolumenBitLocker -Letra $l -ClaveRecuperacion $clave
            $clave = $null
            if ($ok) {
                Write-Log ("Volumen {0} desbloqueado (solo lectura)." -f $l) -Nivel OK
                break
            } else {
                Write-Log ("Clave rechazada para {0} (intento {1}/3)." -f $l, $i) -Nivel AVISO
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Fase 2: chkdsk SIN reparar + estado "dirty"
# ---------------------------------------------------------------------------
function Invoke-RevisionSistemaArchivos {
    param([string[]]$Letras, [string]$CarpetaRegistros)
    $resultados = @()
    foreach ($l in $Letras) {
        if (-not (Test-Path -LiteralPath ($l + '\'))) { continue }
        Write-Log ("chkdsk (solo lectura, sin /f ni /r) en {0} ..." -f $l)
        $archivo = Join-Path $CarpetaRegistros ('chkdsk_{0}.txt' -f $l.Substring(0, 1))
        $r = Invoke-Nativo 'chkdsk.exe' @($l) -ArchivoSalida $archivo
        $texto = $r.Salida -join "`n"
        $ejecutado = $true
        if ($texto -match '(?i)(write.protected|protegid[oa] contra escritura)') {
            # chkdsk se niega en volúmenes protegidos: es la consecuencia esperada del modo solo lectura
            $ejecutado = $false
            $interp = 'No se puede ejecutar sobre un volumen protegido contra escritura (esperado). Ver estado "dirty".'
        } else {
            $interp = switch ($r.Codigo) {
                0 { 'Sin errores' }
                1 { 'Errores corregidos (inesperado en solo lectura)' }
                2 { 'Limpieza menor sugerida (no grave)' }
                3 { 'Errores encontrados o no se pudo revisar: ver registro' }
                default { 'Resultado desconocido (código {0})' -f $r.Codigo }
            }
        }
        $sucio = Invoke-Nativo 'fsutil.exe' @('dirty', 'query', $l)
        $resultados += [pscustomobject]@{
            Volumen        = $l
            Codigo         = $r.Codigo
            Ejecutado      = $ejecutado
            Interpretacion = $interp
            Dirty          = (($sucio.Salida -join ' ').Trim())
            Registro       = $archivo
        }
        $nivel = 'OK'; if ($r.Codigo -ne 0 -and $ejecutado) { $nivel = 'AVISO' }
        Write-Log ("  {0}: {1}" -f $l, $interp) -Nivel $nivel
    }
    return $resultados
}

# ---------------------------------------------------------------------------
# Fase 2: salud del disco (SMART)
# Fuentes, en orden: smartctl.exe (opcional en el USB), contadores de
# fiabilidad de Storage WMI y la predicción de fallo de WMI (solo SATA).
# ---------------------------------------------------------------------------
function Get-SaludDisco {
    param([int]$Numero, [string]$RutaHerramientas, [string]$CarpetaRegistros)
    $res = [ordered]@{
        Veredicto = 'DESCONOCIDO'; Fuente = ''; Detalles = [System.Collections.Generic.List[string]]::new()
    }
    $malo = $false; $dudoso = $false; $algunaFuente = $false
    $archivo = Join-Path $CarpetaRegistros 'smart.txt'
    $texto = [System.Collections.Generic.List[string]]::new()

    # 1) smartctl
    $smartctl = Join-Path $RutaHerramientas 'Smartmontools\smartctl.exe'
    $smartOk = $false
    if (Test-Path -LiteralPath $smartctl) {
        $pr = Test-ArchivosContraAncla -RutaHerramientas $RutaHerramientas -Prefijo 'Smartmontools\'
        if ($pr.Count -eq 0) { $smartOk = $true }
        else { $texto.Add('smartctl NO se ejecuta: no coincide con el ancla (' + ($pr -join '; ') + ')'); $res.Detalles.Add('smartctl omitido por fallo de integridad.') }
    }
    if ($smartOk) {
        $r = Invoke-Nativo $smartctl @('-x', ('/dev/pd{0}' -f $Numero))
        foreach ($l in $r.Salida) { $texto.Add($l) }
        if ($r.Codigo -ge 0 -and ($r.Codigo -band 3) -eq 0) {
            $algunaFuente = $true
            $res.Fuente += 'smartctl '
            if ($r.Codigo -band 8)  { $malo = $true;   $res.Detalles.Add('SMART: el disco reporta FALLO (DISK FAILING).') }
            if ($r.Codigo -band 16) { $malo = $true;   $res.Detalles.Add('SMART: atributos de pre-fallo por debajo del umbral.') }
            if ($r.Codigo -band 32) { $dudoso = $true; $res.Detalles.Add('SMART: atributos de uso superaron el umbral en el pasado.') }
            if ($r.Codigo -band 64) { $dudoso = $true; $res.Detalles.Add('SMART: el registro de errores del disco tiene entradas.') }
            if ($r.Codigo -band 128){ $dudoso = $true; $res.Detalles.Add('SMART: autodiagnósticos con errores.') }
            $todo = $r.Salida -join "`n"
            $m = [regex]::Match($todo, '(?im)^\s*5\s+Reallocated_Sector_Ct\s+.*\s(\d+)\s*$')
            if ($m.Success -and [int64]$m.Groups[1].Value -gt 0) { $dudoso = $true; $res.Detalles.Add('Sectores reasignados: ' + $m.Groups[1].Value) }
            $m = [regex]::Match($todo, '(?im)^\s*197\s+Current_Pending_Sector\s+.*\s(\d+)\s*$')
            if ($m.Success -and [int64]$m.Groups[1].Value -gt 0) { $malo = $true; $res.Detalles.Add('Sectores pendientes (ilegibles): ' + $m.Groups[1].Value) }
            $m = [regex]::Match($todo, '(?im)^\s*Percentage Used:\s+(\d+)%')
            if ($m.Success) { $res.Detalles.Add('NVMe desgaste usado: ' + $m.Groups[1].Value + '%'); if ([int]$m.Groups[1].Value -ge 90) { $dudoso = $true } }
            $m = [regex]::Match($todo, '(?im)^\s*Media and Data Integrity Errors:\s+(\d+)')
            if ($m.Success -and [int64]$m.Groups[1].Value -gt 0) { $malo = $true; $res.Detalles.Add('NVMe errores de integridad de datos: ' + $m.Groups[1].Value) }
        } else {
            $res.Detalles.Add(('smartctl no pudo leer el disco (código {0}).' -f $r.Codigo))
        }
    }

    # 2) Storage WMI
    try {
        $pd = Get-PhysicalDisk -ErrorAction Stop | Where-Object { [string]$_.DeviceId -eq [string]$Numero } | Select-Object -First 1
        if ($pd) {
            $algunaFuente = $true
            $res.Fuente += 'StorageWMI '
            $texto.Add(('PhysicalDisk: {0} Salud={1} Estado={2}' -f $pd.FriendlyName, $pd.HealthStatus, ($pd.OperationalStatus -join ',')))
            if ([string]$pd.HealthStatus -eq 'Unhealthy') { $malo = $true; $res.Detalles.Add('Windows marca el disco como NO saludable.') }
            elseif ([string]$pd.HealthStatus -eq 'Warning') { $dudoso = $true; $res.Detalles.Add('Windows marca el disco con ADVERTENCIA.') }
            try {
                $rc = $pd | Get-StorageReliabilityCounter -ErrorAction Stop
                if ($rc) {
                    $texto.Add(('Fiabilidad: Temp={0} Desgaste={1} ErroresLecturaNoCorregidos={2} HorasEncendido={3}' -f $rc.Temperature, $rc.Wear, $rc.ReadErrorsUncorrected, $rc.PowerOnHours))
                    if ($rc.ReadErrorsUncorrected -gt 0) { $malo = $true; $res.Detalles.Add('Errores de lectura no corregidos: ' + $rc.ReadErrorsUncorrected) }
                    if ($rc.Wear -ge 90) { $dudoso = $true; $res.Detalles.Add('Desgaste reportado: ' + $rc.Wear + '%') }
                }
            } catch { $texto.Add('Contadores de fiabilidad no disponibles en WinPE.') }
        }
    } catch { $texto.Add('Get-PhysicalDisk no disponible.') }

    # 3) (Se quitó la consulta WMI MSStorageDriver_FailurePredictStatus: en algunos
    #    WinPE System.Management cierra PowerShell con un AccessViolation.)

    if ($malo) { $res.Veredicto = 'MALO' }
    elseif ($dudoso) { $res.Veredicto = 'DUDOSO' }
    elseif ($algunaFuente) { $res.Veredicto = 'BUENO' }
    if ($res.Detalles.Count -eq 0) { $res.Detalles.Add('Sin indicadores negativos en las fuentes disponibles.') }
    try { [System.IO.File]::WriteAllLines($archivo, [string[]]$texto, $script:Utf8ConBom) } catch { }
    $obj = [pscustomobject]@{ Veredicto = $res.Veredicto; Fuente = $res.Fuente.Trim(); Detalles = $res.Detalles.ToArray(); Registro = $archivo }
    return $obj
}
