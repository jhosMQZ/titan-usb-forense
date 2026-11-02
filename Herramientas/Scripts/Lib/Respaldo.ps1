<#
    Respaldo.ps1 - Selección de carpetas, inventario SHA-256, copia con
    robocopy y verificación de hashes origen/destino.
#>

# Carpetas conocidas -> nombre del valor en "User Shell Folders" del NTUSER.DAT
$script:CarpetasConocidas = [ordered]@{
    'Documents' = @{ Valor = 'Personal'; Prioridad = 1 }
    'Desktop'   = @{ Valor = 'Desktop'; Prioridad = 2 }
    'Pictures'  = @{ Valor = 'My Pictures'; Prioridad = 3 }
    'Downloads' = @{ Valor = '{374DE290-123F-4565-9164-39C4925E467B}'; Prioridad = 6 }
}

function Get-PerfilesOffline {
    param([string]$VolWindows)
    $res = @()
    $excluir = @('Public', 'Default', 'Default User', 'All Users', 'defaultuser0', 'WDAGUtilityAccount')
    foreach ($d in @(Get-ChildItem -LiteralPath "$VolWindows\Users" -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($excluir -contains $d.Name) { continue }
        if (($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $nt = Join-Path $d.FullName 'NTUSER.DAT'
        if ([System.IO.File]::Exists($nt)) {
            $res += [pscustomobject]@{ Nombre = $d.Name; Ruta = $d.FullName; NtUser = $nt; Hive = $null }
        }
    }
    return $res
}

function Resolve-CarpetaUsuario {
    # Lee la ruta real (posible redirección a OneDrive u otra carpeta).
    param($Perfil, [string]$NombreCarpeta, [string]$VolWindows, [string]$LetraOriginal)
    $defecto = Join-Path $Perfil.Ruta $NombreCarpeta
    if (-not $Perfil.Hive) { return $defecto }
    $valor = $script:CarpetasConocidas[$NombreCarpeta].Valor
    $raw = Get-ValorClave ("{0}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -f $Perfil.Hive) $valor
    if (-not $raw) { return $defecto }
    $exp = Expand-RutaOffline -Texto ([string]$raw) -VolWindows $VolWindows -LetraOriginal $LetraOriginal -Perfil $Perfil.Ruta
    if ($exp -match '^[A-Za-z]:\\' -and (Test-Path -LiteralPath $exp)) { return $exp }
    if ($exp -notmatch ('^(?i)' + [regex]::Escape($VolWindows))) {
        Write-Log ("La carpeta {0} de {1} está redirigida a '{2}' (otra unidad). Agréguela a mano si existe." -f $NombreCarpeta, $Perfil.Nombre, $raw) -Nivel AVISO
    }
    return $defecto
}

function Get-CarpetasRespaldo {
    param($Ctx)
    $lista = [System.Collections.Generic.List[object]]::new()
    $vw = $Ctx.VolWindows
    foreach ($pf in @($Ctx.Perfiles)) {
        foreach ($nc in @($Ctx.Config.CarpetasUsuario)) {
            if (-not $script:CarpetasConocidas.Contains([string]$nc)) { continue }
            $ruta = Resolve-CarpetaUsuario -Perfil $pf -NombreCarpeta $nc -VolWindows $vw -LetraOriginal $Ctx.Sistema.LetraOriginal
            if (Test-Path -LiteralPath $ruta) {
                $lista.Add([pscustomobject]@{ Etiqueta = "$($pf.Nombre)\$nc"; Origen = $ruta; Prioridad = $script:CarpetasConocidas[$nc].Prioridad; Tipo = 'Usuario' })
            }
        }
        foreach ($cand in @($Ctx.Config.CarpetasProyectosCandidatas)) {
            $c = [string]$cand
            if ($c -notmatch '(?i)%USERPROFILE%') { continue }
            $p = $c -replace '(?i)%USERPROFILE%', ($pf.Ruta -replace '\$', '$$$$')
            foreach ($it in @(Get-Item -Path $p -Force -ErrorAction SilentlyContinue)) {
                if ($it.PSIsContainer) { $lista.Add([pscustomobject]@{ Etiqueta = 'Proyectos\' + (Get-NombreSeguro $it.FullName); Origen = $it.FullName; Prioridad = 4; Tipo = 'Proyecto' }) }
            }
        }
    }
    foreach ($cand in @($Ctx.Config.CarpetasProyectosCandidatas)) {
        $c = [string]$cand
        if ($c -notmatch '(?i)%SYSTEMDRIVE%') { continue }
        $p = $c -replace '(?i)%SYSTEMDRIVE%', $vw
        foreach ($it in @(Get-Item -Path $p -Force -ErrorAction SilentlyContinue)) {
            if ($it.PSIsContainer) { $lista.Add([pscustomobject]@{ Etiqueta = 'Proyectos\' + (Get-NombreSeguro $it.FullName); Origen = $it.FullName; Prioridad = 4; Tipo = 'Proyecto' }) }
        }
    }

    # Revisión interactiva
    while ($true) {
        $lista = Remove-CarpetasAnidadas $lista
        Write-Host ''
        Write-Host 'Carpetas que se respaldarán:' -ForegroundColor Cyan
        for ($i = 0; $i -lt $lista.Count; $i++) {
            Write-Host ('  [{0,2}] {1,-40} {2}' -f ($i + 1), $lista[$i].Etiqueta, $lista[$i].Origen)
        }
        if (@($Ctx.Config.ExcluirCarpetasEnRespaldo).Count -gt 0) {
            Write-Host ('  Subcarpetas excluidas por configuración: {0}' -f (@($Ctx.Config.ExcluirCarpetasEnRespaldo) -join ', ')) -ForegroundColor DarkYellow
        }
        Write-Host ''
        Write-Host '  A = agregar carpeta (ej. D:\MisProyectos)   Q = quitar por número   C = continuar' -ForegroundColor Gray
        $op = Read-Opcion -Pregunta 'Opción [C]' -Opciones @('A', 'Q', 'C') -PorDefecto 'C'
        if ($op -eq 'C') { break }
        if ($op -eq 'A') {
            $r = ([string](Read-Host 'Ruta completa tal como se ve en WinPE')).Trim().Trim('"')
            if ($r -eq '') { continue }
            if (-not (Test-Path -LiteralPath $r -PathType Container)) { Write-Host 'No existe esa carpeta.' -ForegroundColor Yellow; continue }
            $enObjetivo = $false
            foreach ($v in $Ctx.Volumenes) { if (Test-RutaDentroDe -Ruta $r -Carpeta $v) { $enObjetivo = $true } }
            if (-not $enObjetivo) {
                Write-Host 'Solo se admiten carpetas del disco analizado (que está en solo lectura). Para otro disco, haga una segunda pasada eligiéndolo.' -ForegroundColor Yellow
                continue
            }
            $lista.Add([pscustomobject]@{ Etiqueta = 'Adicional\' + (Get-NombreSeguro $r); Origen = $r.TrimEnd('\'); Prioridad = 5; Tipo = 'Adicional' })
        }
        if ($op -eq 'Q') {
            $n = 0
            if ([int]::TryParse(([string](Read-Host 'Número a quitar')), [ref]$n) -and $n -ge 1 -and $n -le $lista.Count) { $lista.RemoveAt($n - 1) }
        }
    }
    # Destinos únicos
    $usados = @{}
    $final = @()
    $ordenada = @($lista | Sort-Object -Property @('Prioridad', 'Etiqueta'))
    foreach ($c in $ordenada) {
        $et = $c.Etiqueta; $k = 2
        while ($usados.ContainsKey($et.ToLowerInvariant())) { $et = '{0}_{1}' -f $c.Etiqueta, $k; $k++ }
        $usados[$et.ToLowerInvariant()] = $true
        $final += [pscustomobject]@{
            Etiqueta = $et; Origen = $c.Origen; Destino = (Join-Path $Ctx.Dirs.Respaldo $et)
            Prioridad = $c.Prioridad; Tipo = $c.Tipo; Archivos = ([System.Collections.Generic.List[object]]::new())
            BytesPendientes = [int64]0; Incluida = $true; ResultadoCopia = ''; CodigoCopia = $null; Metodo = ''
        }
    }
    return $final
}

function Remove-CarpetasAnidadas {
    # Si una carpeta está dentro de otra de la lista, se deja solo la exterior.
    param($Lista)
    $res = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $Lista) {
        $anidada = $false; $duplicada = $false
        foreach ($b in $Lista) {
            if ([object]::ReferenceEquals($a, $b)) { continue }
            if ($a.Origen -ieq $b.Origen) { $duplicada = $true }
            elseif (Test-RutaDentroDe -Ruta $a.Origen -Carpeta $b.Origen) { $anidada = $true }
        }
        if ($anidada) { continue }
        if ($duplicada) {
            $ya = $false
            foreach ($r in $res) { if ($r.Origen -ieq $a.Origen) { $ya = $true } }
            if ($ya) { continue }
        }
        $res.Add($a)
    }
    return , $res
}

function Get-RaizDeArchivo {
    # Índice de la carpeta de respaldo que contiene la ruta, o -1
    param([string]$Ruta, $Carpetas)
    for ($i = 0; $i -lt $Carpetas.Count; $i++) {
        if (Test-RutaDentroDe -Ruta $Ruta -Carpeta $Carpetas[$i].Origen) { return $i }
    }
    return -1
}

function Test-EnCarpetaExcluida {
    param([string]$Relativa, [string[]]$Nombres)
    foreach ($n in $Nombres) {
        if ($Relativa -match ('(?i)(^|\\)' + [regex]::Escape($n) + '\\')) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Fase 5: inventario + SHA-256 (+ heurísticas en carpetas de respaldo)
# ---------------------------------------------------------------------------
function Invoke-Inventario {
    param($Ctx, [string[]]$Raices)
    $csv = Join-Path $Ctx.Dirs.Datos 'inventario_sha256.csv'
    $w = New-EscritorCsv -Ruta $csv -Columnas @('Ruta', 'Tamano', 'UltimaModificacionUtc', 'Atributos', 'SHA256', 'Estado')
    $hashPorRuta = @{}
    $stats = [ordered]@{ Archivos = [int64]0; Bytes = [int64]0; Errores = [int64]0; SoloNube = [int64]0; Enlaces = [int64]0; Heuristicas = 0 }
    $excluir = @($Ctx.Config.ExcluirCarpetasEnRespaldo | ForEach-Object { [string]$_ })
    $prefijos = @($Ctx.Carpetas | ForEach-Object { $_.Origen.TrimEnd('\') + '\' })
    $ultimo = [DateTime]::Now
    try {
        foreach ($raiz in $Raices) {
            Write-Log ("Inventariando y calculando SHA-256 en {0} ..." -f $raiz)
            # Canalización (pipeline) para procesar en streaming: un "foreach" sobre
            # la función cargaría millones de objetos en memoria antes de empezar.
            Get-ArchivosRecursivo -Raiz $raiz -Fase 'Inventario' | ForEach-Object {
                $f = $_
                $ruta = Get-RutaCorta $f.FullName
                $attr = [int]$f.Attributes
                $tam = [int64]0
                try { $tam = $f.Length } catch { }
                $mod = ''
                try { $mod = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } catch { }
                $hash = ''; $estado = 'OK'; $cab = $null
                $nube = Test-SoloNube $attr
                # Enlaces simbólicos de archivo: no se siguen (podrían apuntar a
                # dispositivos, a otros discos o al propio USB)
                $enlace = $false
                if (-not $nube -and (($attr -band $script:ATTR_REPARSE) -ne 0)) {
                    # Solo enlaces simbólicos y uniones; otros tipos (compresión WOF,
                    # OneDrive descargado) se leen normalmente.
                    $enlace = Test-EsEnlaceSimbolico -Ruta $ruta
                }
                if ($nube) {
                    $estado = 'SOLO_NUBE'; $stats.SoloNube++
                } elseif ($enlace) {
                    $estado = 'ENLACE (no se sigue)'; $stats.Enlaces++
                } else {
                    try { $h = Get-Sha256Archivo -Ruta $ruta; $hash = $h.Hash; $cab = $h.Cabecera }
                    catch {
                        $estado = 'ERROR: ' + $_.Exception.Message
                        $stats.Errores++
                        Add-RegistroError -Fase 'Inventario' -Ruta $ruta -Mensaje $_.Exception.Message -Silencioso
                    }
                }
                # Atributos en hexadecimal: los marcadores de OneDrive usan bits que
                # el enum FileAttributes de .NET no define (convertirlos fallaría).
                Write-FilaCsv -Escritor $w -Valores @($ruta, $tam, $mod, ('0x{0:X}' -f $attr), $hash, $estado)
                $stats.Archivos++; $stats.Bytes += $tam

                # Búsqueda de la carpeta de respaldo en línea (millones de archivos)
                $idx = -1
                for ($k = 0; $k -lt $prefijos.Count; $k++) {
                    if ($ruta.StartsWith($prefijos[$k], [System.StringComparison]::OrdinalIgnoreCase)) { $idx = $k; break }
                }
                if ($idx -ge 0) {
                    $c = $Ctx.Carpetas[$idx]
                    $rel = $ruta.Substring($c.Origen.TrimEnd('\').Length).TrimStart('\')
                    $excl = Test-EnCarpetaExcluida -Relativa $rel -Nombres $excluir
                    $c.Archivos.Add([pscustomobject]@{
                            Ruta = $ruta; Relativa = $rel; Tamano = $tam; Hash = $hash
                            Nube = $nube; Offline = (($attr -band $script:ATTR_OFFLINE) -ne 0)
                            Enlace = $enlace; Excluido = $excl; Error = ($estado -like 'ERROR*')
                        })
                    if ($hash) { $hashPorRuta[$ruta.ToLowerInvariant()] = $hash }
                    if (-not $nube -and -not $enlace -and -not $excl) {
                        $hz = Test-HeuristicasArchivo -Ruta $ruta -Nombre $f.Name -Cabecera $cab
                        if ($hz) {
                            Add-Sospechoso -Ruta $ruta -Motivo $hz.Motivo -Motor 'Heurística' -Severidad $hz.Severidad
                            $stats.Heuristicas++
                            Write-Log ("HEURÍSTICA ({0}): {1} - {2}" -f $hz.Severidad, $ruta, $hz.Motivo) -Nivel DET
                        }
                    }
                }
                if (([DateTime]::Now - $ultimo).TotalSeconds -ge 2) {
                    $ultimo = [DateTime]::Now
                    Write-Progress -Activity 'Inventario SHA-256' -Status ('{0:N0} archivos, {1}' -f $stats.Archivos, (Format-Bytes $stats.Bytes)) -CurrentOperation $ruta
                }
            }
        }
    } finally {
        $w.Dispose()
        Write-Progress -Activity 'Inventario SHA-256' -Completed
    }
    Write-Log ("Inventario: {0:N0} archivos, {1}, {2:N0} errores de lectura, {3:N0} solo en la nube." -f $stats.Archivos, (Format-Bytes $stats.Bytes), $stats.Errores, $stats.SoloNube) -Nivel OK
    return [pscustomobject]@{ HashPorRuta = $hashPorRuta; Stats = [pscustomobject]$stats; Csv = $csv }
}

# ---------------------------------------------------------------------------
# Fase 6: espacio y copia
# ---------------------------------------------------------------------------
function Get-BytesPendientes {
    param($Carpeta)
    $t = [int64]0
    foreach ($a in $Carpeta.Archivos) {
        if ($a.Nube -or $a.Enlace -or $a.Excluido -or (Test-EnCuarentena $a.Ruta)) { continue }
        $t += $a.Tamano
    }
    return $t
}

function Confirm-EspacioDisponible {
    param($Ctx)
    $margen = [int64]$Ctx.Config.MargenLibreMB * 1MB
    while ($true) {
        $libre = (Get-EspacioLibre $Ctx.RutaRespaldo) - $margen
        $total = [int64]0
        foreach ($c in $Ctx.Carpetas) { $c.BytesPendientes = Get-BytesPendientes $c; if ($c.Incluida) { $total += $c.BytesPendientes } }
        Write-Host ''
        Write-Host ('Espacio necesario: {0}   Libre en el USB (menos margen): {1}' -f (Format-Bytes $total), (Format-Bytes $libre)) -ForegroundColor Cyan
        if ($total -le $libre) { return $true }
        Write-Log 'NO hay espacio suficiente en el USB para todo el respaldo.' -Nivel AVISO
        for ($i = 0; $i -lt $Ctx.Carpetas.Count; $i++) {
            $c = $Ctx.Carpetas[$i]
            $marca = ' '; if ($c.Incluida) { $marca = 'X' }
            Write-Host ('  [{0}] {1,2}. {2,-40} {3,12}' -f $marca, ($i + 1), $c.Etiqueta, (Format-Bytes $c.BytesPendientes))
        }
        $op = Read-Opcion -Pregunta 'Número para incluir/excluir, C = copiar igual (lo que quepa), S = salir sin copiar' -Opciones (@('C', 'S') + (1..$Ctx.Carpetas.Count | ForEach-Object { [string]$_ })) -PorDefecto ''
        if ($op -eq 'C') { return $true }
        if ($op -eq 'S') { return $false }
        $n = [int]$op
        $Ctx.Carpetas[$n - 1].Incluida = -not $Ctx.Carpetas[$n - 1].Incluida
    }
}

function Get-TieneBackupPrivilege {
    try {
        $r = Invoke-Nativo 'whoami.exe' @('/priv')
        return (($r.Salida -join ' ') -match 'SeBackupPrivilege')
    } catch { return $false }
}

function Get-DescripcionRobocopy {
    param([int]$Codigo)
    if ($Codigo -lt 0) { return 'robocopy no se ejecutó' }
    if ($Codigo -ge 16) { return 'ERROR GRAVE: robocopy no copió nada (ver registro)' }
    $p = @()
    if ($Codigo -band 1) { $p += 'archivos copiados' }
    if ($Codigo -band 2) { $p += 'archivos extra en destino' }
    if ($Codigo -band 4) { $p += 'discrepancias' }
    if ($Codigo -band 8) { $p += 'ALGUNOS ARCHIVOS NO SE COPIARON tras los reintentos' }
    if ($p.Count -eq 0) { return 'nada que copiar (sin cambios)' }
    return ($p -join ', ')
}

function Invoke-CopiaRespaldo {
    param($Ctx)
    New-Item -ItemType Directory -Path $Ctx.Dirs.Respaldo -Force | Out-Null
    $usarB = Get-TieneBackupPrivilege
    $excluirDirs = @($Ctx.Config.ExcluirCarpetasEnRespaldo | ForEach-Object { [string]$_ })
    $i = 0
    foreach ($c in @($Ctx.Carpetas | Sort-Object Prioridad)) {
        $i++
        if (-not $c.Incluida) { $c.ResultadoCopia = 'Omitida por el usuario (espacio)'; continue }
        New-Item -ItemType Directory -Path $c.Destino -Force | Out-Null
        # Exclusiones exactas: archivos en cuarentena + marcadores de nube sin atributo Offline
        $xf = @()
        foreach ($a in $c.Archivos) {
            if ((Test-EnCuarentena $a.Ruta) -or ($a.Nube -and -not $a.Offline)) { $xf += $a.Ruta }
        }
        $largo = 0; foreach ($x in $xf) { $largo += $x.Length + 3 }
        $log = Join-Path $Ctx.Dirs.Registros ('robocopy_{0:00}.log' -f $i)
        Write-Log ("Copiando {0} -> {1} ({2} excluidos por cuarentena/nube)" -f $c.Origen, $c.Destino, $xf.Count)
        if ($largo -lt 20000) {
            $argRobo = @($c.Origen, $c.Destino, '/E', '/COPY:DAT', '/DCOPY:DAT',
                ('/R:{0}' -f [int]$Ctx.Config.RobocopyReintentos), ('/W:{0}' -f [int]$Ctx.Config.RobocopyEspera),
                '/XJD', '/XJF', '/XA:O', '/NP', '/NDL', '/TEE', ('/UNILOG+:' + $log))
            if ([int]$Ctx.Config.RobocopyHilos -gt 1) { $argRobo += ('/MT:{0}' -f [int]$Ctx.Config.RobocopyHilos) }
            if ($usarB) { $argRobo += '/B' }
            if ($excluirDirs.Count -gt 0) { $argRobo += '/XD'; $argRobo += $excluirDirs }
            if ($xf.Count -gt 0) { $argRobo += '/XF'; $argRobo += $xf }
            $codigo = Invoke-NativoEnVivo -Programa 'robocopy.exe' -Argumentos $argRobo
            $c.CodigoCopia = $codigo
            $c.Metodo = 'robocopy'
            $c.ResultadoCopia = Get-DescripcionRobocopy $codigo
            if ($codigo -ge 8 -or $codigo -lt 0) { Add-RegistroError -Fase 'Copia' -Ruta $c.Origen -Mensaje ('robocopy {0}: {1}' -f $codigo, $c.ResultadoCopia) }
        } else {
            Write-Log 'Demasiadas exclusiones para la línea de comandos de robocopy: se usa el copiador interno con las mismas reglas.' -Nivel AVISO
            $res = Invoke-CopiadorInterno -Carpeta $c -Log $log -Reintentos ([int]$Ctx.Config.RobocopyReintentos) -Espera ([int]$Ctx.Config.RobocopyEspera)
            $c.Metodo = 'interno'
            $c.CodigoCopia = $res.Fallidos
            $c.ResultadoCopia = ('{0} copiados, {1} fallidos' -f $res.Copiados, $res.Fallidos)
        }
        Write-Log ("  Resultado: {0}" -f $c.ResultadoCopia)
    }
}

function Invoke-CopiadorInterno {
    # Copia equivalente a /COPY:DAT (datos, atributos, fechas) sin robocopy.
    param($Carpeta, [string]$Log, [int]$Reintentos = 2, [int]$Espera = 5)
    $copiados = 0; $fallidos = 0
    $sw = New-Object System.IO.StreamWriter -ArgumentList $Log, $true, $script:Utf8ConBom
    try {
        foreach ($a in $Carpeta.Archivos) {
            if ($a.Excluido) { continue }
            if ($a.Nube) { $sw.WriteLine("OMITIDO (solo nube)`t$($a.Ruta)"); continue }
            if ($a.Enlace) { $sw.WriteLine("OMITIDO (enlace simbólico)`t$($a.Ruta)"); continue }
            if (Test-EnCuarentena $a.Ruta) { $sw.WriteLine("OMITIDO (cuarentena)`t$($a.Ruta)"); continue }
            $dst = Join-Path $Carpeta.Destino $a.Relativa
            $ok = $false; $msg = ''
            for ($t = 0; $t -le $Reintentos; $t++) {
                try {
                    $dirDst = Split-Path -Path $dst -Parent
                    [void][System.IO.Directory]::CreateDirectory((Get-RutaLarga $dirDst))
                    $src = Get-RutaLarga $a.Ruta
                    $d = Get-RutaLarga $dst
                    [System.IO.File]::Copy($src, $d, $true)
                    $fi = New-Object System.IO.FileInfo -ArgumentList $src
                    [System.IO.File]::SetCreationTimeUtc($d, $fi.CreationTimeUtc)
                    [System.IO.File]::SetLastWriteTimeUtc($d, $fi.LastWriteTimeUtc)
                    # Solo atributos básicos (R, H, S, A): los de nube/offline no se copian
                    [System.IO.File]::SetAttributes($d, [System.IO.FileAttributes]([int]$fi.Attributes -band 0x27))
                    $ok = $true; break
                } catch { $msg = $_.Exception.Message; Start-Sleep -Seconds $Espera }
            }
            if ($ok) { $copiados++; $sw.WriteLine("COPIADO`t$($a.Ruta)") }
            else { $fallidos++; $sw.WriteLine("ERROR`t$($a.Ruta)`t$msg"); Add-RegistroError -Fase 'Copia' -Ruta $a.Ruta -Mensaje $msg -Silencioso }
        }
    } finally { $sw.Dispose() }
    return [pscustomobject]@{ Copiados = $copiados; Fallidos = $fallidos }
}

# ---------------------------------------------------------------------------
# Fase 7: verificación origen vs destino
# ---------------------------------------------------------------------------
function Invoke-VerificacionCopia {
    param($Ctx, [hashtable]$HashesCuarentena)
    $csv = Join-Path $Ctx.Dirs.Datos 'verificacion.csv'
    $w = New-EscritorCsv -Ruta $csv -Columnas @('Carpeta', 'RutaOrigen', 'RutaDestino', 'SHA256Origen', 'SHA256Destino', 'Resultado')
    $st = [ordered]@{ OK = 0; Diferente = 0; Falta = 0; Nube = 0; Cuarentena = 0; Excluido = 0; Enlaces = 0; ErrorLectura = 0; Fugas = 0; BytesCopiados = [int64]0; NoIncluida = 0; Marcados = 0; MarcasFallidas = 0 }
    $marcar = [bool]$Ctx.Config.MarcarOrigenInternet
    $ultimo = [DateTime]::Now; $n = 0
    try {
        foreach ($c in $Ctx.Carpetas) {
            foreach ($a in $c.Archivos) {
                $n++
                $dst = Join-Path $c.Destino $a.Relativa
                $existeDst = Test-ArchivoExiste $dst
                $res = ''; $hd = ''
                if (Test-EnCuarentena $a.Ruta) {
                    $st.Cuarentena++
                    if ($existeDst) {
                        $res = 'FUGA_CORREGIDA (se copió un archivo en cuarentena; movido a Cuarentena)'
                        Move-FugaACuarentena -Ctx $Ctx -RutaDestino $dst -RutaOrigen $a.Ruta
                        $st.Fugas++
                    } else { $res = 'EXCLUIDO_CUARENTENA' }
                } elseif (-not $c.Incluida) { $res = 'CARPETA_NO_INCLUIDA'; $st.NoIncluida++ }
                elseif ($a.Excluido) { $res = 'EXCLUIDO_POR_CONFIGURACION'; $st.Excluido++ }
                elseif ($a.Nube) { $res = 'SOLO_NUBE (no estaba en el disco)'; $st.Nube++ }
                elseif ($a.Enlace) {
                    $res = 'EXCLUIDO_ENLACE (enlace simbólico, no se sigue)'; $st.Enlaces++
                    if ($existeDst) { $res = 'FUGA_CORREGIDA (enlace copiado)'; Move-FugaACuarentena -Ctx $Ctx -RutaDestino $dst -RutaOrigen $a.Ruta; $st.Fugas++ }
                }
                elseif (-not $existeDst) {
                    if ($a.Error) { $res = 'ERROR_LECTURA_ORIGEN'; $st.ErrorLectura++ } else { $res = 'FALTA_EN_DESTINO'; $st.Falta++ }
                } else {
                    try {
                        $hd = (Get-Sha256Archivo -Ruta $dst).Hash
                        $ho = $a.Hash
                        if (-not $ho) { $ho = (Get-Sha256Archivo -Ruta $a.Ruta).Hash; $a.Hash = $ho }
                        if ($HashesCuarentena.ContainsKey($hd)) {
                            $res = 'FUGA_CORREGIDA (contenido idéntico a un archivo en cuarentena)'
                            Move-FugaACuarentena -Ctx $Ctx -RutaDestino $dst -RutaOrigen $a.Ruta
                            $st.Fugas++
                        } elseif ($hd -eq $ho) {
                            $res = 'OK'; $st.OK++; $st.BytesCopiados += $a.Tamano
                        } else { $res = 'DIFERENTE'; $st.Diferente++ }
                    } catch {
                        $res = 'ERROR_VERIFICACION: ' + $_.Exception.Message; $st.ErrorLectura++
                    }
                    # Marca de la Web en la copia (después del hash: no altera el contenido)
                    if ($marcar -and $res -notlike 'FUGA*' -and (Test-ArchivoExiste $dst)) {
                        try { Set-MarcaInternet -Ruta $dst; $st.Marcados++ }
                        catch { $st.MarcasFallidas++; Write-Log ("No se pudo marcar como de Internet: {0}" -f $dst) -SoloArchivo }
                    }
                }
                Write-FilaCsv -Escritor $w -Valores @($c.Etiqueta, $a.Ruta, $dst, $a.Hash, $hd, $res)
                if (([DateTime]::Now - $ultimo).TotalSeconds -ge 2) {
                    $ultimo = [DateTime]::Now
                    Write-Progress -Activity 'Verificando hashes del respaldo' -Status ('{0:N0} archivos revisados' -f $n) -CurrentOperation $a.Ruta
                }
            }
        }
    } finally {
        $w.Dispose()
        Write-Progress -Activity 'Verificando hashes del respaldo' -Completed
    }
    $nivel = 'OK'
    if ($st.Diferente -gt 0 -or $st.Falta -gt 0 -or $st.Fugas -gt 0) { $nivel = 'AVISO' }
    Write-Log ("Verificación: {0:N0} OK, {1:N0} diferentes, {2:N0} faltan, {3:N0} en cuarentena, {4:N0} solo nube, {5:N0} fugas corregidas." -f $st.OK, $st.Diferente, $st.Falta, $st.Cuarentena, $st.Nube, $st.Fugas) -Nivel $nivel
    return [pscustomobject]$st
}

function Move-FugaACuarentena {
    # Defensa en profundidad: si un archivo marcado llegó al respaldo, se cifra
    # en Cuarentena y se elimina SOLO la copia del USB (nunca el original).
    param($Ctx, [string]$RutaDestino, [string]$RutaOrigen)
    try {
        $nombre = 'FUGA_{0}_{1}.cuar' -f (Get-Date -Format 'HHmmssfff'), (Get-NombreSeguro ([System.IO.Path]::GetFileName($RutaOrigen)) 40)
        $dest = Join-Path $Ctx.Dirs.Cuarentena $nombre
        [void](Protect-ArchivoCuarentena -Origen $RutaDestino -Destino $dest)
        $larga = Get-RutaLarga $RutaDestino
        [System.IO.File]::SetAttributes($larga, [System.IO.FileAttributes]::Normal)
        [System.IO.File]::Delete($larga)
        Write-Log ("Fuga corregida: {0} (copia del USB cifrada y retirada del respaldo)" -f $RutaDestino) -Nivel AVISO
    } catch {
        Add-RegistroError -Fase 'Verificación' -Ruta $RutaDestino -Mensaje ('No se pudo corregir la fuga: ' + $_.Exception.Message)
    }
}
