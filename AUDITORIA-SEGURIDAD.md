# Auditoría de seguridad del kit USB forense

Fecha: 30 de octubre de 2026 · Alcance: todos los scripts de `Construir\`, `Ancla\` y `Herramientas\`.

## Modelo de amenazas

| Actor / origen | Qué controla | Qué podría intentar |
|---|---|---|
| Malware en el disco analizado | Nombres de archivo, contenido, registro, tareas, accesos directos, enlaces, marcadores falsos | Que el USB lo active en escritura, ocultarse del antivirus, explotar los analizadores, contaminar el respaldo o el reporte |
| Manipulación del USB (física o por un equipo comprometido) | Archivos de las particiones del USB | Cambiar scripts, ClamAV o `boot.wim` para ejecutar código como SYSTEM |
| Cadena de suministro | ZIP de ClamAV, binarios copiados | Introducir binarios alterados |
| Fuga de datos | Registros, temporales, red | Exponer claves de BitLocker, copias del registro o malware sin cifrar |

## Hallazgos y correcciones

| # | Severidad | Hallazgo | Corrección aplicada |
|---|---|---|---|
| 1 | **Crítica** | Al arrancar, un disco con un archivo `USB-FORENSE.marker` se trataba como USB de trabajo y se le **quitaba la solo lectura**. El malware podía plantar ese archivo en el disco analizado. | El USB se identifica por una **firma de disco MBR aleatoria** (generada con RNG criptográfico) sellada en `X:\Ancla\usb-id.txt`. Ningún otro disco pierde nunca la solo lectura. Las particiones se buscan solo dentro de ese disco. |
| 2 | **Alta** | La huella que se muestra al arrancar la calcula código del propio USB: quien modificara a la vez herramientas y `boot.wim` podía falsearla. | Nuevo `Verificar-USB.ps1` en el PC técnico: compara **todo** el USB (incluidos `boot.wim`, gestor de arranque y BCD) con referencias guardadas en el PC. `Actualizar-Firmas` y `Actualizar-Ancla` lo ejecutan antes de hacer nada. |
| 3 | **Alta** | Si la integridad fallaba, se podía continuar escribiendo "CONTINUAR BAJO MI RIESGO" y ejecutar código no verificado como SYSTEM. | Eliminada la anulación. Con el código alterado el análisis queda **bloqueado**; solo se puede abrir consola, reiniciar o apagar. |
| 4 | **Alta** | ClamAV cargaba **todo** lo que hubiera en `database\`: una lista blanca `.ign2`/`.fp` añadida podía ocultar malware. | Solo se cargan `main.cvd`, `daily.cvd` y `bytecode.cvd` (firmados). Lo demás se ignora y se reporta. |
| 5 | **Alta** | La clave de recuperación de BitLocker se tecleaba visible y quedaba en `Registros\consola.txt` (transcripción) en el USB. | Entrada oculta (`SecureString`), liberada de memoria tras usarla. Igual en `Escanear-Con-Defender.ps1`. |
| 6 | Media | Los accesos directos de Inicio se leían con `WScript.Shell` (código del Shell de Windows procesando un `.lnk` hostil, como SYSTEM). | Analizador propio del formato `.lnk` con comprobación de límites; un `.lnk` dañado suma puntos de sospecha. |
| 7 | Media | XML de tareas cargado sin desactivar DTD (riesgo de "billion laughs"). | `DtdProcessing=Prohibit`, sin resolvedor, tope de 2 M caracteres y de 1 MB por archivo. `ClassId` COM validado como GUID. |
| 8 | Media | Se seguían enlaces simbólicos de archivo al calcular hashes y copiar (podían apuntar a otro disco, a un dispositivo o al propio USB). | Se detectan por la etiqueta de reanálisis (`fsutil`) y no se siguen; robocopy usa `/XJD /XJF`; ClamAV `--follow-*-symlinks=0`. |
| 9 | Media | WinPE iniciaba la red por defecto (superficie remota, posible exfiltración). | `wpeinit` con `EnableNetwork=false`, firewall activo. |
| 10 | Media | Binarios de ClamAV ejecutados desde el USB sin re-comprobar justo antes (ventana entre la verificación y la ejecución). | Se re-verifican contra el ancla inmediatamente antes de ejecutar ClamAV y smartctl, y se rechazan DLL/EXE sobrantes (secuestro de DLL). |
| 11 | Media | Sin comprobación de origen de ClamAV ni del runtime VC++. | Se exige firma Authenticode válida (Cisco / Microsoft) y, opcionalmente, el SHA-256 publicado del ZIP. |
| 12 | Media | WinPE quedaba con los parches de la fecha del ADK mientras procesa datos hostiles (registro, sistemas de archivos). | Parámetro `-ActualizacionAcumulada` para integrar la última actualización acumulativa en `boot.wim`. Se quitó `WinPE-DismCmdlets` (no se usaba). |
| 13 | Media | Las copias del respaldo se abrían en el PC sano como archivos locales "de confianza". | Marca de la Web (`Zone.Identifier`, zona Internet) en cada copia: SmartScreen y Vista protegida de Office actúan. |
| 14 | Baja | Nombres de archivo con saltos de línea, ESC o RLO podían falsear líneas del registro, la consola o el reporte. | Limpieza de controles y marcadores bidireccionales (se muestran como `[U+202E]`) en consola, registro y HTML. CSV neutraliza también tabulador y retorno al inicio. |
| 15 | Baja | Temporales de un análisis interrumpido (copias del registro, archivos extraídos por ClamAV) quedaban en el USB sin cifrar. | Se borran al siguiente arranque y al iniciar el análisis; `Verificar-USB` los avisa y `-LimpiarTemporales` los elimina. |
| 16 | Baja | Herramientas del sistema invocadas por nombre (dependían del PATH). | Rutas absolutas a `System32` en WinPE y en el PC técnico. |
| 17 | Baja | Detecciones externas (CSV de Defender) aceptaban rutas con `..` o `:`. | Se rechazan. |
| 18 | Baja | `config.json` sin validar. | Rangos y formatos validados al iniciar; rutas con `..` rechazadas. |
| 19 | Baja | `Restaurar-Cuarentena` usaba el nombre original sin limpiar y no avisaba fuera de una VM. | Nombre saneado con prefijo de Id, comprobación de máquina virtual y Marca de la Web en el archivo restaurado. |
| 20 | Baja | Se podía elegir como objetivo el disco de arranque del entorno (solo en pruebas fuera de WinPE). | Bloqueado (`IsBoot`/`IsSystem`). Además se re-comprueba la solo lectura al inicio de cada fase. |

## Riesgos residuales (aceptados y documentados)

- **Analizadores del sistema**: el kernel de WinPE carga copias de los hives del registro y monta el sistema de archivos del disco analizado; ClamAV analiza archivos hostiles como SYSTEM. Se mitiga con la actualización acumulativa, ClamAV al día, sin red y con el disco en solo lectura, pero no se puede eliminar.
- **Firmware/UEFI comprometido** en el PC analizado: queda fuera del alcance de un USB de arranque. Secure Boot activo reduce el riesgo para el propio USB.
- **Detección imperfecta**: ningún antivirus lo detecta todo; por eso existen la Marca de la Web y el análisis del respaldo con Defender antes de abrirlo.
- **Clave de cuarentena pública** (`infected`): es intencional; el cifrado sirve para volver inertes los archivos, no para ocultarlos.
- **Pruebas en hardware real limitadas**: la sintaxis y la lógica se verifican con el analizador de PowerShell y con los simulacros `PROBAR-TITAN.bat` y `PROBAR-BLACKBOX.bat`, y el kit se ha probado en pocos equipos. Haz una prueba completa en un PC sano antes del uso real.
