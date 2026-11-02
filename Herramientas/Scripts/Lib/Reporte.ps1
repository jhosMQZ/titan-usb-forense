<#
    Reporte.ps1 - Reporte final en HTML (autocontenido, sin JavaScript) y TXT.
    Todo texto que viene del equipo analizado se escapa (ConvertTo-HtmlSeguro)
    para que un nombre de archivo malicioso no pueda inyectar HTML.
#>

function Get-Recomendaciones {
    param($R)
    $rec = [System.Collections.Generic.List[string]]::new()
    if ($R.Detecciones -gt 0) {
        $rec.Add('Se detectó malware. No vuelva a usar ese Windows tal cual: tras recuperar los datos, reinstale Windows desde un medio oficial (formateando la partición).')
        $rec.Add('Cambie desde OTRO equipo limpio las contraseñas de correo, bancos y redes sociales usadas en ese PC, y active la verificación en dos pasos.')
    }
    if ($R.PersistenciaAlta -gt 0) {
        $rec.Add('Hay mecanismos de inicio con severidad ALTA: revise persistencia.csv. Si no los reconoce, trátelos como compromiso del sistema aunque el antivirus no detecte nada.')
    }
    if ($R.Salud -eq 'MALO') {
        $rec.Add('El disco muestra señales de FALLO. Priorice clonar el disco (imagen sector a sector) a uno sano y reemplácelo. No ejecute chkdsk /f ni reparaciones sobre el disco original.')
    } elseif ($R.Salud -eq 'DUDOSO') {
        $rec.Add('El disco tiene advertencias de salud: haga una segunda copia de seguridad cuanto antes y planee reemplazarlo.')
    }
    if ($R.ChkdskErrores -gt 0) {
        $rec.Add('chkdsk encontró problemas en el sistema de archivos. SOLO después de tener el respaldo verificado, puede ejecutar "chkdsk X: /f" desde el entorno de recuperación (eso sí escribe en el disco).')
    }
    if ($R.VerifDiferentes -gt 0 -or $R.VerifFaltan -gt 0) {
        $rec.Add('Algunos archivos no se copiaron o no coinciden: revise verificacion.csv (filtre por DIFERENTE / FALTA_EN_DESTINO) y los robocopy_*.log, y repita la copia de esas carpetas.')
    }
    if ($R.VerifNube -gt 0) {
        $rec.Add('Hay archivos que solo estaban en la nube (OneDrive). No están en el disco: recupérelos iniciando sesión en OneDrive desde un equipo sano.')
    }
    if ($R.Fugas -gt 0) {
        $rec.Add('Se detectaron y corrigieron fugas a la copia (archivos sospechosos que llegaron al respaldo). Revise el registro; analice el respaldo con Defender antes de abrirlo.')
    }
    if ($R.FirmasAntiguas) {
        $rec.Add('Las firmas de ClamAV tenían más días de los permitidos: actualícelas (Construir\Actualizar-Firmas.ps1) y repita el análisis.')
    }
    if (-not $R.AntivirusEjecutado) {
        $rec.Add('NO se ejecutó el escaneo antivirus: el respaldo NO está verificado como limpio. Analícelo con Microsoft Defender actualizado antes de abrir cualquier archivo.')
    }
    if ([string]$R.SecureBoot -ne 'ACTIVO') {
        $rec.Add('El análisis se hizo con Secure Boot desactivado o no verificable. Si lo desactivó para arrancar el USB, vuelva a activarlo en la UEFI del equipo.')
    }
    if ($R.Marcados -gt 0) {
        $rec.Add('Las copias del respaldo llevan la "Marca de la Web" (zona Internet): al abrirlas en el PC sano, SmartScreen revisará los ejecutables y Office abrirá los documentos en Vista protegida. No la quite salvo en archivos que haya revisado.')
    }
    if (-not $R.IntegridadFinalOk) {
        $rec.Add('La verificación de integridad del USB al final NO fue correcta: no confíe en este USB hasta reconstruirlo desde el PC técnico.')
    }
    $rec.Add('Antes de abrir el respaldo, conéctelo a un PC sano y actualizado y analícelo con Microsoft Defender (clic derecho > Examinar con Microsoft Defender). Nunca abra el respaldo en el PC analizado.')
    $rec.Add('Guarde la carpeta del caso completa (Datos, Registros, Reporte): los hashes SHA-256 permiten demostrar más adelante que los archivos no cambiaron.')
    return $rec
}

function New-Reporte {
    param($Ctx, $R)
    $rec = Get-Recomendaciones -R $R
    $carpetaRep = $Ctx.Dirs.Reporte
    New-Item -ItemType Directory -Path $carpetaRep -Force | Out-Null

    # ----------------------------- TXT ------------------------------------
    $t = [System.Collections.Generic.List[string]]::new()
    $t.Add('REPORTE DE ANÁLISIS Y RESPALDO - USB FORENSE')
    $t.Add('=' * 60)
    $t.Add(('Fecha: {0}    Duración total: {1}' -f $R.Fecha, $R.Duracion))
    $t.Add(('Equipo: {0}  |  {1} {2} (build {3})' -f $R.Equipo, $R.Producto, $R.Version, $R.Build))
    $t.Add(('Disco analizado: #{0} {1} ({2})  - montado en SOLO LECTURA: {3}' -f $R.DiscoNumero, $R.DiscoModelo, $R.DiscoTamano, $R.SoloLectura))
    $t.Add(('Modo: {0}   |   Secure Boot: {1}' -f $R.Modo, $R.SecureBoot))
    $t.Add('')
    $t.Add('VEREDICTO');                 $t.Add('---------'); $t.Add($R.Veredicto); $t.Add('')
    $t.Add('SALUD DEL DISCO');           $t.Add('---------------')
    $t.Add(('SMART: {0} (fuentes: {1})' -f $R.Salud, $R.SaludFuente))
    foreach ($d in $R.SaludDetalles) { $t.Add('  - ' + $d) }
    foreach ($c in $R.Chkdsk) { $t.Add(('chkdsk {0}: {1} | {2}' -f $c.Volumen, $c.Interpretacion, $c.Dirty)) }
    $t.Add('')
    $t.Add('MALWARE');                   $t.Add('-------')
    $t.Add(('Motor: {0}' -f $R.ClamVersion))
    $t.Add(('Archivos escaneados por ClamAV: {0:N0}  | Detecciones: {1}  | Errores de lectura: {2}' -f $R.Escaneados, $R.Detecciones, $R.ErroresEscaneo))
    $t.Add(('Detecciones importadas de Defender: {0}  | Heurísticas: {1}' -f $R.Externas, $R.Heuristicas))
    $t.Add(('En cuarentena: {0} archivos ({1})' -f $R.EnCuarentena, $R.BytesCuarentena))
    foreach ($q in $R.ListaCuarentena) { $t.Add(('  {0} [{1}] {2} -> {3}' -f $q.Id, $q.Severidad, $q.RutaOriginal, $q.Motivos)) }
    $t.Add('')
    $t.Add('PERSISTENCIA');              $t.Add('------------')
    $t.Add(('Alta: {0}  Media: {1}  Baja: {2}' -f $R.PersistenciaAlta, $R.PersistenciaMedia, $R.PersistenciaBaja))
    foreach ($p in $R.ListaPersistencia) { $t.Add(('  [{0}] {1} | {2} | {3} | {4}' -f $p.Severidad, $p.Categoria, $p.Nombre, $p.Valor, $p.Motivos)) }
    $t.Add('')
    $t.Add('RESPALDO');                  $t.Add('--------')
    foreach ($c in $R.Carpetas) { $t.Add(('  {0,-40} {1}' -f $c.Etiqueta, $c.ResultadoCopia)) }
    $t.Add(('Verificados OK: {0:N0} ({1})  Diferentes: {2}  Faltan: {3}  Solo nube: {4}  Excluidos: {5}  Errores lectura: {6}  Fugas corregidas: {7}  Enlaces no seguidos: {8}  Marcados como de Internet: {9}' -f $R.VerifOK, $R.BytesCopiados, $R.VerifDiferentes, $R.VerifFaltan, $R.VerifNube, $R.VerifExcluidos, $R.VerifErrores, $R.Fugas, $R.Enlaces, $R.Marcados))
    $t.Add(('Espacio en el USB: usado por este caso {0} | libre al terminar {1}' -f $R.EspacioCaso, $R.EspacioLibre))
    $t.Add('')
    $t.Add('INTEGRIDAD DEL USB');        $t.Add('------------------')
    $t.Add(('Inicio: {0}  | Final: {1}  | Huella del ancla: {2}' -f $R.IntegridadInicial, $R.IntegridadFinal, $R.Huella))
    $t.Add('')
    $t.Add(('ERRORES REGISTRADOS: {0} (ver Datos\errores.csv)' -f $R.TotalErrores))
    $t.Add('')
    $t.Add('RECOMENDACIONES');           $t.Add('---------------')
    $k = 1; foreach ($x in $rec) { $t.Add(('{0}. {1}' -f $k, $x)); $k++ }
    $t.Add('')
    $t.Add('Archivos de datos: Datos\inventario_sha256.csv, cuarentena.csv, persistencia.csv, verificacion.csv, errores.csv')
    [System.IO.File]::WriteAllLines((Join-Path $carpetaRep 'reporte.txt'), [string[]]$t, $script:Utf8ConBom)

    # ----------------------------- HTML -----------------------------------
    $h = New-Object System.Text.StringBuilder
    $e = { param($x) ConvertTo-HtmlSeguro $x }
    $colorVer = '#1a7f37'
    if ($R.NivelVeredicto -eq 'ROJO') { $colorVer = '#c62828' } elseif ($R.NivelVeredicto -eq 'AMARILLO') { $colorVer = '#b26a00' }
    [void]$h.AppendLine('<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$h.AppendLine('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''">')
    [void]$h.AppendLine('<title>Reporte USB Forense</title><style>')
    [void]$h.AppendLine('body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f5f7;color:#1d1d1f}main{max-width:1100px;margin:0 auto;padding:16px}')
    [void]$h.AppendLine('h1{font-size:1.5em}h2{font-size:1.15em;border-bottom:2px solid #d0d7de;padding-bottom:4px;margin-top:28px}')
    [void]$h.AppendLine('.tarjetas{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}.t{background:#fff;border-radius:8px;padding:12px;box-shadow:0 1px 2px #0002}')
    [void]$h.AppendLine('.t b{display:block;font-size:1.5em}.ver{color:#fff;padding:14px;border-radius:8px;font-weight:600}')
    [void]$h.AppendLine('table{border-collapse:collapse;width:100%;background:#fff;font-size:.85em}th,td{border:1px solid #d0d7de;padding:5px;text-align:left;vertical-align:top;word-break:break-all}th{background:#eef1f4}')
    [void]$h.AppendLine('.Alta,.Infectado{color:#c62828;font-weight:600}.Media{color:#b26a00;font-weight:600}.Baja{color:#555}.nota{color:#555;font-size:.85em}ol li{margin-bottom:6px}')
    [void]$h.AppendLine('</style></head><body><main>')
    [void]$h.AppendLine(('<h1>Reporte de análisis y respaldo</h1><p class="nota">{0} &middot; duración {1} &middot; modo {2}</p>' -f (& $e $R.Fecha), (& $e $R.Duracion), (& $e $R.Modo)))
    [void]$h.AppendLine(('<div class="ver" style="background:{0}">{1}</div>' -f $colorVer, (& $e $R.Veredicto)))
    [void]$h.AppendLine('<h2>Resumen</h2><div class="tarjetas">')
    $tarj = @(
        @('Detecciones', $R.Detecciones), @('En cuarentena', $R.EnCuarentena), @('Persistencia alta', $R.PersistenciaAlta),
        @('Salud del disco', $R.Salud), @('Archivos verificados OK', ('{0:N0}' -f $R.VerifOK)), @('Copiado', $R.BytesCopiados),
        @('Diferentes / faltan', ('{0} / {1}' -f $R.VerifDiferentes, $R.VerifFaltan)), @('Errores registrados', $R.TotalErrores)
    )
    foreach ($x in $tarj) { [void]$h.AppendLine(('<div class="t">{0}<b>{1}</b></div>' -f (& $e $x[0]), (& $e $x[1]))) }
    [void]$h.AppendLine('</div>')

    [void]$h.AppendLine('<h2>Equipo y disco</h2><table>')
    $filasEq = @(
        @('Nombre del equipo', $R.Equipo), @('Sistema', ('{0} {1} (build {2})' -f $R.Producto, $R.Version, $R.Build)),
        @('Disco', ('#{0} {1} - {2}' -f $R.DiscoNumero, $R.DiscoModelo, $R.DiscoTamano)), @('Solo lectura confirmado', $R.SoloLectura),
        @('Secure Boot durante el análisis', $R.SecureBoot),
        @('Volúmenes analizados', ($R.Volumenes -join ', ')), @('SMART', ('{0} ({1})' -f $R.Salud, $R.SaludFuente)),
        @('Detalles SMART', ($R.SaludDetalles -join ' | '))
    )
    foreach ($c in $R.Chkdsk) { $filasEq += , @(('chkdsk ' + $c.Volumen), ('{0} | {1}' -f $c.Interpretacion, $c.Dirty)) }
    foreach ($x in $filasEq) { [void]$h.AppendLine(('<tr><th>{0}</th><td>{1}</td></tr>' -f (& $e $x[0]), (& $e $x[1]))) }
    [void]$h.AppendLine('</table>')

    [void]$h.AppendLine('<h2>Malware y cuarentena</h2>')
    [void]$h.AppendLine(('<p>Motor: {0}. Archivos escaneados: {1:N0}. Errores de lectura durante el escaneo: {2}. Detecciones Defender importadas: {3}. Heurísticas: {4}.</p>' -f (& $e $R.ClamVersion), $R.Escaneados, $R.ErroresEscaneo, $R.Externas, $R.Heuristicas))
    if (@($R.ListaCuarentena).Count -gt 0) {
        [void]$h.AppendLine('<table><tr><th>Id</th><th>Severidad</th><th>Ruta original</th><th>Motivo</th><th>Estado</th><th>SHA-256</th></tr>')
        foreach ($q in (@($R.ListaCuarentena) | Select-Object -First 500)) {
            [void]$h.AppendLine(('<tr><td>{0}</td><td class="{1}">{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f (& $e $q.Id), (& $e $q.Severidad), (& $e $q.RutaOriginal), (& $e $q.Motivos), (& $e $q.Estado), (& $e $q.SHA256)))
        }
        [void]$h.AppendLine('</table><p class="nota">Lista completa: Datos\cuarentena.csv. Los archivos están cifrados (.cuar) en la carpeta Cuarentena.</p>')
    } else { [void]$h.AppendLine('<p>No hay archivos en cuarentena.</p>') }

    [void]$h.AppendLine('<h2>Persistencia (inicio automático)</h2>')
    if (@($R.ListaPersistencia).Count -gt 0) {
        [void]$h.AppendLine('<table><tr><th>Severidad</th><th>Categoría</th><th>Nombre</th><th>Comando / valor</th><th>Motivos</th><th>Firma digital</th></tr>')
        foreach ($p in (@($R.ListaPersistencia) | Select-Object -First 500)) {
            [void]$h.AppendLine(('<tr><td class="{0}">{0} ({1})</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f (& $e $p.Severidad), $p.Puntos, (& $e $p.Categoria), (& $e $p.Nombre), (& $e $p.Valor), (& $e $p.Motivos), (& $e $p.Firma)))
        }
        [void]$h.AppendLine('</table><p class="nota">Solo se muestran entradas con severidad Media o Alta. Todo: Datos\persistencia.csv. "NotSigned" en archivos de Windows es normal en WinPE (firmados por catálogo).</p>')
    } else { [void]$h.AppendLine('<p>Sin entradas de severidad media o alta.</p>') }

    [void]$h.AppendLine('<h2>Respaldo</h2><table><tr><th>Carpeta</th><th>Origen</th><th>Método</th><th>Resultado</th></tr>')
    foreach ($c in $R.Carpetas) {
        [void]$h.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (& $e $c.Etiqueta), (& $e $c.Origen), (& $e $c.Metodo), (& $e $c.ResultadoCopia)))
    }
    [void]$h.AppendLine('</table>')
    [void]$h.AppendLine(('<p>Verificación SHA-256: <b>{0:N0}</b> OK ({1}), {2} diferentes, {3} faltan, {4} solo en la nube, {5} excluidos por configuración, {6} con error de lectura, {7} fugas corregidas, {8} enlaces simbólicos no seguidos. {9:N0} copias marcadas como "de Internet".</p>' -f $R.VerifOK, (& $e $R.BytesCopiados), $R.VerifDiferentes, $R.VerifFaltan, $R.VerifNube, $R.VerifExcluidos, $R.VerifErrores, $R.Fugas, $R.Enlaces, $R.Marcados))
    [void]$h.AppendLine(('<p>Espacio usado por este caso: {0}. Libre en el USB al terminar: {1}.</p>' -f (& $e $R.EspacioCaso), (& $e $R.EspacioLibre)))

    [void]$h.AppendLine('<h2>Integridad del USB</h2>')
    [void]$h.AppendLine(('<p>Al inicio: <b>{0}</b> &middot; Al final: <b>{1}</b> &middot; Huella del ancla: <code>{2}</code> (compárela con la que anotó al crear el USB).</p>' -f (& $e $R.IntegridadInicial), (& $e $R.IntegridadFinal), (& $e $R.Huella)))

    [void]$h.AppendLine(('<h2>Errores ({0})</h2>' -f $R.TotalErrores))
    if (@($R.ListaErrores).Count -gt 0) {
        [void]$h.AppendLine('<table><tr><th>Fase</th><th>Ruta</th><th>Mensaje</th></tr>')
        foreach ($x in (@($R.ListaErrores) | Select-Object -First 200)) {
            [void]$h.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (& $e $x.Fase), (& $e $x.Ruta), (& $e $x.Mensaje)))
        }
        [void]$h.AppendLine('</table><p class="nota">Lista completa: Datos\errores.csv</p>')
    } else { [void]$h.AppendLine('<p>Sin errores.</p>') }

    [void]$h.AppendLine('<h2>Recomendaciones</h2><ol>')
    foreach ($x in $rec) { [void]$h.AppendLine(('<li>{0}</li>' -f (& $e $x))) }
    [void]$h.AppendLine('</ol><p class="nota">Generado por Analizar-Equipo.ps1 en WinPE. Datos: inventario_sha256.csv, cuarentena.csv, persistencia.csv, verificacion.csv, errores.csv (separador ;).</p>')
    [void]$h.AppendLine('</main></body></html>')
    [System.IO.File]::WriteAllText((Join-Path $carpetaRep 'reporte.html'), $h.ToString(), $script:Utf8ConBom)
    return $rec
}
