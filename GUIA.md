# USB forense con WinPE: análisis sin conexión y respaldo seguro

Kit para crear un USB booteable (64 GB) que arranca un PC con Windows 11 que no inicia, analiza su disco **sin ejecutar nada de él**, busca malware y persistencia, y copia tus archivos limpios al USB con verificación por hash.

**Reglas que el kit garantiza**

| Regla | Cómo se cumple |
|---|---|
| Disco en solo lectura | WinPE arranca con la política SAN *OfflineAll* (ningún disco se monta solo). El analizador activa el disco **ya con el atributo de solo lectura**, y se detiene si no lo puede confirmar. |
| Nunca ejecutar archivos del equipo | Solo se leen bytes (hash, antivirus, XML de tareas). El registro se analiza sobre **copias** de los hives. Los accesos directos se leen sin abrirse. |
| Nunca borrar nada | No se usa `--remove` ni `--move` de ClamAV, Defender corre con `-DisableRemediation`. Lo sospechoso se **copia cifrado** a `Cuarentena` con su motivo en `cuarentena.csv`. |

---

## 1. Estructura

### 1.1 El kit (en tu PC técnico)

```
titan-usb-forense\
├─ GUIA.md                         ← esta guía
├─ Construir\                      ← se ejecuta en el PC TÉCNICO SANO
│  ├─ Crear-USB.ps1                ← construye todo el USB
│  ├─ Actualizar-Firmas.ps1        ← firmas de ClamAV (antes de cada uso)
│  ├─ Actualizar-Ancla.ps1         ← re-sella el USB si cambias scripts
│  ├─ Verificar-USB.ps1            ← verificación FUERTE antes y después de cada uso
│  ├─ Escanear-Con-Defender.ps1    ← opcional: segunda opinión con Defender
│  ├─ Restaurar-Cuarentena.ps1     ← descifra un archivo en cuarentena (en una VM)
│  └─ Manifiesto.ps1               ← funciones compartidas (hash/manifiesto)
├─ Ancla\                          ← se incrusta DENTRO de boot.wim (X:\Ancla)
│  ├─ Iniciar.ps1                  ← punto de entrada de confianza + verificación
│  ├─ startnet.cmd                 ← arranque de WinPE (sin red, firewall activo)
│  └─ unattend.xml                 ← respuestas de wpeinit (EnableNetwork=false)
└─ Herramientas\                   ← contenido de la partición HERRAMIENTAS
   ├─ USB-FORENSE.marker
   ├─ INICIAR.bat
   ├─ ClamAV\  (freshclam.conf, LEEME; Crear-USB añade los binarios y database\)
   ├─ Smartmontools\ (opcional smartctl.exe)
   └─ Scripts\
      ├─ Analizar-Equipo.ps1       ← orquestador de las 8 fases
      ├─ config.json               ← carpetas, límites, exclusiones
      └─ Lib\ Comun.ps1, Disco.ps1, Malware.ps1, Persistencia.ps1, Respaldo.ps1, Reporte.ps1
```

### 1.2 El USB terminado

| Partición | Formato | Tamaño | Contenido |
|---|---|---|---|
| **WINPE** | FAT32 | 2 GB | Arranque UEFI + `sources\boot.wim` (incluye `X:\Ancla` con el manifiesto de hashes y la identidad del USB) |
| **HERRAMIENTAS** | NTFS | 8 GB | Scripts, ClamAV, firmas, smartctl. Se verifica por hash en cada arranque |
| **RESPALDO** | NTFS | resto (~48 GB) | `Casos\<fecha>\` y `Entrada\` |

Cada análisis crea:

```
RESPALDO:\Casos\20261030_141500\
├─ Respaldo\     <perfil>\Documents, Desktop, Pictures, Downloads, Proyectos\...
├─ Cuarentena\   Q0001_<hash>.cuar (cifrado) + Q0001_<hash>.json (motivo, ruta, hash)
├─ Datos\        inventario_sha256.csv, cuarentena.csv, persistencia.csv,
│                verificacion.csv, errores.csv     (separador ; para Excel en español)
├─ Registros\    principal.log, consola.txt, clamscan_NN.log, robocopy_NN.log,
│                chkdsk_X.txt, smart.txt, integridad_final.txt
└─ Reporte\      reporte.html, reporte.txt
```

---

## 2. Requisitos

En el **PC técnico** (sano, Windows 10/11 x64, con Internet):

1. **Windows ADK** y el **complemento WinPE** (los dos instaladores) desde la página oficial de Microsoft: *Download and install the Windows ADK*. Usa la versión más reciente para Windows 11 (10.1.26100.2454 o posterior, con su parche de servicio). En el instalador del ADK basta marcar **Deployment Tools**.
2. **ClamAV portable**: `clamav-<versión>.win.x64.zip` desde clamav.net/downloads (al escribir esto, la rama estable es 1.5.x). No lo descomprimas; el script lo hace.
3. **Microsoft Visual C++ 2015-2022 Redistributable (x64)** instalado (normalmente ya lo está). WinPE no trae ese runtime y el script copia sus DLL junto a ClamAV.
4. Opcional: **smartmontools** para Windows (aporta `smartctl.exe`, salud SMART detallada).
5. Opcional: controladores de almacenamiento (Intel **VMD/RST**) si el disco no aparece en WinPE (ver §8).
6. Un USB de 64 GB (se borrará entero) y espacio libre en C: (~5 GB).

En el **PC dañado**: arranque UEFI desde USB y, de ser posible, 8 GB de RAM o más (ClamAV carga sus firmas en memoria).

---

## 3. Crear el USB paso a paso

1. Copia la carpeta `titan-usb-forense` al PC técnico, por ejemplo a `C:\titan-usb-forense`.
2. Desbloquea los scripts descargados (si vienen de Internet, Windows los marca):
   ```powershell
   Get-ChildItem C:\titan-usb-forense -Recurse | Unblock-File
   ```
3. Abre **PowerShell como administrador** y permite scripts solo en esa sesión:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   cd C:\titan-usb-forense\Construir
   ```
4. Conecta el USB de 64 GB y ejecuta:
   ```powershell
   .\Crear-USB.ps1 -ClamAVZip "$env:USERPROFILE\Downloads\clamav-1.5.2.win.x64.zip" `
                   -Smartctl 'C:\Program Files\smartmontools\bin\smartctl.exe'
   ```
   Parámetros de seguridad recomendados:
   - `-ClamAVSha256 <hash>`: SHA-256 publicado del ZIP (página de descargas de ClamAV o GitHub). Si no coincide, se detiene.
   - `-ActualizacionAcumulada C:\Descargas\windows11.0-kb....msu`: la última actualización acumulativa de Windows 11 (misma versión que el ADK, x64) del *Microsoft Update Catalog*. Parchea el kernel y los analizadores de WinPE, que van a procesar datos de un equipo comprometido.

   Otros: `-Controladores C:\Drivers\VMD` (agrega .inf a WinPE), `-DiscoUSB 2`, `-CertificadoArranque 2011` (solo equipos antiguos, ver §4), `-SinActualizarFirmas`, `-PermitirClamAVSinFirma` (solo si verificaste el ZIP por hash y los binarios no traen firma).
5. El script hace, en orden:
   1. Comprueba ADK, complemento WinPE y el ZIP (SHA-256 si lo diste) y genera una **identidad aleatoria del USB** (firma de disco).
   2. Prepara HERRAMIENTAS (scripts + ClamAV + runtime VC++ + smartctl) y exige **firma Authenticode válida** de Cisco en los binarios de ClamAV y de Microsoft en el runtime.
   3. Genera el **manifiesto SHA-256** y su **huella**.
   4. `copype amd64` (imagen base de WinPE).
   5. Monta `boot.wim` y agrega solo lo necesario: WinPE-WMI, WinPE-NetFX, WinPE-Scripting, WinPE-PowerShell, WinPE-StorageWMI, WinPE-SecureStartup (BitLocker), WinPE-EnhancedStorage (+ en-us). Aplica la actualización acumulativa si la diste. Fija espacio temporal de 512 MB, la política SAN *OfflineAll*, copia el ancla (`X:\Ancla`: verificador, manifiesto, identidad del USB, `unattend.xml`) y `startnet.cmd`.
   6. Pide confirmación escribiendo `BORRAR <n>`, particiona el USB (WINPE / HERRAMIENTAS / RESPALDO) y le graba la identidad.
   7. `MakeWinPEMedia /UFD ... /bootex` (arranque firmado con **Windows UEFI CA 2023**) y guarda **en el PC técnico** la referencia de hashes de la partición de arranque (`referencia_winpe.sha256`).
   8. Copia HERRAMIENTAS, prepara RESPALDO y descarga las firmas de ClamAV.
   9. Verificación completa con `Verificar-USB` contra la referencia del PC.
6. **Anota la huella** que muestra al final (por ejemplo `3F9A-11C0-7B2E-D45A`) en papel o en tu teléfono. También queda en `C:\WinPE_USBForense\HUELLA-ANCLA.txt`.
7. **No borres `C:\WinPE_USBForense\`**: ahí están `manifest.sha256`, `referencia_winpe.sha256` y `usb-id.txt`, que son la referencia de confianza para verificar el USB. Si los pierdes, reconstruye el USB.

Equivalente manual (por si quieres entender cada comando; se ejecuta en *Deployment and Imaging Tools Environment* como administrador):

```cmd
copype amd64 C:\WinPE_USBForense\winpe
dism /Mount-Image /ImageFile:"C:\WinPE_USBForense\winpe\media\sources\boot.wim" /Index:1 /MountDir:"C:\WinPE_USBForense\winpe\mount"
dism /Image:"C:\WinPE_USBForense\winpe\mount" /Add-Package /PackagePath:"%WinPERoot%\amd64\WinPE_OCs\WinPE-WMI.cab"
rem ... repetir para cada componente y su en-us\<componente>_en-us.cab ...
dism /Image:"C:\WinPE_USBForense\winpe\mount" /Set-ScratchSpace:512
dism /Unmount-Image /MountDir:"C:\WinPE_USBForense\winpe\mount" /Commit
MakeWinPEMedia /UFD C:\WinPE_USBForense\winpe P: /bootex
```

---

## 4. Secure Boot y medios firmados

**Qué protege:** con Secure Boot activo, el firmware solo arranca un gestor de arranque firmado por Microsoft, y el kernel de WinPE solo carga controladores firmados. Eso impide que un bootkit (malware de arranque) se cuele en la cadena de inicio del USB.

**Qué NO protege:** los scripts y ClamAV no los verifica Secure Boot. Por eso existe el **ancla de integridad** (§6.1).

**El cambio de certificados de 2026.** Los certificados de Secure Boot de 2011 vencen en 2026; el que firma el gestor de arranque de Windows (*Microsoft Windows Production PCA 2011*) vence el 19 de octubre de 2026 y su reemplazo es **Windows UEFI CA 2023**. Los equipos actualizados que ya revocaron el gestor antiguo **no arrancan** medios firmados con la CA 2011. Por eso el kit usa, por defecto:

```
MakeWinPEMedia /UFD <carpeta> P: /bootex
```

`/bootex` existe desde el ADK 10.1.26100.2454 (diciembre de 2024). Si tu ADK es anterior, actualízalo o usa el script oficial `Make2023BootableMedia.ps1` (artículo de soporte KB5053484).

**Qué hacer en el PC dañado**

1. Entra a la UEFI/BIOS (F2, F10, F12, Supr o Esc según marca) y deja **Secure Boot activado**.
2. Arranca desde el USB con el menú de arranque (F12/F11/Esc/F9). Elige la entrada **UEFI: <nombre del USB>**.
3. Si aparece *Secure Boot Violation*: el firmware del equipo no tiene aún la CA 2023. Opciones, de más a menos segura: actualizar la UEFI del fabricante; reconstruir el USB con `-CertificadoArranque 2011`; como último recurso desactivar Secure Boot solo durante el análisis y **volver a activarlo** después.
4. Controladores agregados con `-Controladores` deben estar firmados (los de Intel VMD/RST del fabricante lo están); un controlador sin firma no carga con Secure Boot.

---

## 5. Usar el USB en el PC dañado

1. Desconecta otros USB y discos externos que no vayas a analizar.
2. Arranca desde el USB (§4). Verás `Iniciando USB forense...`.
3. `Iniciar.ps1`:
   - Arranca **sin red** y con firewall activo.
   - Reconoce el USB de trabajo por su **firma de disco** sellada en el ancla (no por archivos que alguien podría copiar al disco analizado) y solo a ese le permite escritura; cualquier otro disco queda fuera de línea y en solo lectura.
   - Verifica la integridad de HERRAMIENTAS y la firma digital de las bases de ClamAV. Si el **código** no es íntegro, el análisis queda **bloqueado** (no hay forma de saltarlo).
   - Muestra el estado de Secure Boot y la **HUELLA DEL ANCLA**: debe ser idéntica a la que anotaste.
   - Copia los scripts verificados a la RAM y muestra el menú.
4. Elige **1. Analizar el equipo y respaldar archivos**. Recorrido:

| Fase | Qué ves / qué decides |
|---|---|
| 0 Comprobaciones | WinPE, Storage WMI, RAM, USB detectado |
| 1 Detección | Tabla de discos; eliges el disco (el USB aparece marcado como excluido). Resumen → escribe `SI`. Se aplica SOLO LECTURA. Si hay BitLocker, pide la clave de recuperación (48 dígitos, en account.microsoft.com/devices/recoverykey desde otro equipo). Eliges perfiles de usuario y revisas la lista de carpetas (A = agregar, Q = quitar, C = continuar). Confirmas con `SI`. |
| 2 Disco | chkdsk **sin** /f ni /r y SMART. Si la salud es MALA o DUDOSA te ofrece **modo rescate** (escanea y hashea solo tus carpetas para no desgastar el disco) o salir para clonarlo antes. |
| 3 Malware | ClamAV recorre todo el disco (ocultos y comprimidos). Advierte si las firmas tienen más de 7 días. Importa detecciones de Defender si existen en `Entrada\`. |
| 4 Persistencia | Inicio, Run/RunOnce, Winlogon, AppInit, IFEO, LSA, BootExecute, tareas (XML y TaskCache), servicios y controladores. |
| 5 Inventario | SHA-256 de todos los archivos → `inventario_sha256.csv` + heurísticas (doble extensión, ejecutable disfrazado, RLO, accesos directos con intérpretes). |
| 6 Copia | Cuarentena cifrada → comprueba espacio (si no cabe, eliges qué carpetas excluir) → robocopy `/E /COPY:DAT /DCOPY:DAT /R:2 /W:5 /XJD /XA:O /UNILOG+` excluyendo **exactamente** los archivos en cuarentena. |
| 7 Verificación | SHA-256 de cada archivo en destino vs. origen. Si algo marcado llegó al respaldo (fuga), se cifra en cuarentena y se retira del respaldo. |
| 8 Reporte | `reporte.html` y `reporte.txt`, re-verificación de integridad del USB, limpieza de temporales propios. |

**Duración orientativa** (SSD, 500 GB ocupados): chkdsk 5-30 min, ClamAV 3-8 h, SHA-256 1-2 h, copia según volumen. En disco mecánico, el doble o más. Conecta el cargador.

**Configuración** (`Herramientas\Scripts\config.json`, cambia con Actualizar-Ancla):

| Clave | Por defecto | Para qué |
|---|---|---|
| `CarpetasUsuario` | Documents, Desktop, Downloads, Pictures | Carpetas de perfil (se detecta la redirección a OneDrive) |
| `CarpetasProyectosCandidatas` | source\repos, Projects, Proyectos, dev, MetaQuotes\...\MQL5, C:\Proyectos, C:\dev, xampp\htdocs, laragon\www | Se agregan si existen. `*` admite comodines |
| `ExcluirCarpetasEnRespaldo` | `node_modules` | No se copian (se regeneran con `npm install`). Vacía la lista `[]` para incluirlas |
| `HashAlcance` | `TodoElDisco` | O `SoloRespaldo` para ahorrar horas |
| `ClamAV.MaxFileSizeMB` / `MaxScanSizeMB` | 1000 / 2000 | Archivos mayores no se analizan completos (ClamAV no admite más de ~2 GB por archivo) |
| `ClamAV.DetectarPUA` | false | `true` marca también "programas potencialmente no deseados" (más falsos positivos en herramientas de desarrollo) |
| `CuarentenaMaxMB` | 1024 | Más grande: solo se registra (ruta + hash), no se copia |
| `DiasMaxAntiguedadFirmas` | 7 | Aviso de firmas antiguas |
| `MarcarOrigenInternet` | true | Añade la Marca de la Web a cada copia del respaldo (ver §6.3) |

Los valores se validan al iniciar: un `config.json` con rangos absurdos o rutas con `..` detiene el análisis.

---

## 6. Seguridad del USB

### 6.1 Scripts en partición aparte con verificación de hash

- Las herramientas viven en **HERRAMIENTAS**; tus datos en **RESPALDO**. El análisis nunca escribe en HERRAMIENTAS.
- `Crear-USB.ps1` calcula el SHA-256 de cada archivo de HERRAMIENTAS (`manifest.sha256`) y guarda esa lista **dentro de `boot.wim`** (`X:\Ancla`), junto con el verificador `Iniciar.ps1` y la identidad del USB.
- **Dos niveles de verificación:**

| Dónde | Qué comprueba | Para qué sirve |
|---|---|---|
| Al arrancar el USB (`Iniciar.ps1`) | HERRAMIENTAS contra el ancla, sobrantes, firmas `.cvd`; vuelve a comprobar ClamAV y smartctl justo antes de ejecutarlos | Detecta daños y cambios en HERRAMIENTAS. Si el código falla, bloquea el análisis |
| En el PC técnico (`Verificar-USB.ps1`) | **Todo el USB** —incluido `boot.wim`, el gestor de arranque y el BCD— contra referencias guardadas **en tu PC** | Es la verificación fuerte: no depende de nada que esté en el USB. Alguien que modificara a la vez herramientas y `boot.wim` podría engañar al verificador del arranque, pero no a este |

- Los scripts se ejecutan desde una copia en RAM (X:) verificada de nuevo, así que no pueden cambiar a mitad del análisis.
- Las bases `.cvd` se excluyen del manifiesto porque cambian a diario, pero se verifican por su **firma digital de Cisco Talos**, y ClamAV carga **solo** `main.cvd`, `daily.cvd` y `bytecode.cvd`: un archivo extra (por ejemplo una lista blanca `.ign2` que ocultara malware) se ignora y se reporta.
- **Rutina:** `Verificar-USB.ps1` antes de cada uso y al volver de cada equipo analizado. Si cambiaste un script o `config.json`, usa `Actualizar-Ancla.ps1`: primero comprueba que el USB no estaba alterado (si lo estaba, se niega a re-sellarlo), te muestra qué archivos cambian, re-sella `boot.wim` y actualiza las referencias del PC.

### 6.2 Actualizar las firmas antes de cada uso

En el PC técnico, con el USB conectado:

```powershell
cd C:\titan-usb-forense\Construir
.\Actualizar-Firmas.ps1
```

Primero verifica **todo el USB** contra la referencia del PC (si algo no coincide, no ejecuta nada del USB en tu PC), luego descarga bases completas `.cvd`, verifica la firma de cada una y guarda `ClamAV\database\firmas_info.txt`. Si ves "cool-down" o error 429, el CDN de ClamAV te está limitando: espera unas horas. Si avisa **OUTDATED**, descarga la versión nueva de ClamAV y reconstruye con `Crear-USB.ps1`.

### 6.3 Evitar que el USB se infecte

- **Nunca** arranques el Windows dañado con el USB conectado. El USB solo se conecta: (a) en el PC técnico sano, (b) en el PC dañado **arrancando desde el USB**. En WinPE no corre nada del Windows analizado.
- **No abras el respaldo en el PC analizado**, ni siquiera tras "limpiarlo". Ábrelo solo en un equipo sano después de analizarlo: clic derecho sobre `Casos\<fecha>\Respaldo` → *Examinar con Microsoft Defender* (o `MpCmdRun -Scan -ScanType 3 -File R:\Casos\...`).
- **Marca de la Web:** cada copia del respaldo lleva `Zone.Identifier` (zona Internet). En el PC sano, SmartScreen revisa los ejecutables y Office abre los documentos en *Vista protegida* con macros bloqueadas, igual que con un archivo descargado. No altera el contenido ni los hashes. Si copias el respaldo a otra unidad NTFS la marca viaja con él; en FAT32/exFAT se pierde.
- **Sin red:** WinPE arranca con `EnableNetwork=false` y firewall activo. Nada sale ni entra durante el análisis.
- **Clave de BitLocker oculta:** se escribe sin eco y no queda en `consola.txt` ni en los registros.
- **Formatos hostiles:** los accesos directos `.lnk` se leen con un analizador propio con límites (no con el Shell de Windows), los XML de tareas sin DTD y con tope de tamaño, los enlaces simbólicos no se siguen, y todo texto del equipo analizado se limpia de caracteres de control y de inversión (RLO) antes de mostrarse.
- Los temporales de un análisis interrumpido (copias del registro, archivos extraídos por ClamAV) se borran automáticamente al siguiente arranque; `Verificar-USB.ps1 -LimpiarTemporales` también los elimina desde el PC técnico.
- La cuarentena está **cifrada** (`.cuar`, AES-256 con la clave convencional `infected`): no se puede ejecutar por accidente y ningún antivirus la borrará del USB. No la descifres salvo en una VM aislada (`Restaurar-Cuarentena.ps1`).
- El reporte HTML se genera sin JavaScript y con política de contenido estricta, y todo texto del equipo analizado va escapado: un nombre de archivo malicioso no puede inyectar código en el reporte. Los CSV neutralizan fórmulas de Excel.
- Antes de cada uso: `Actualizar-Firmas.ps1` y, al arrancar, compara la huella. Si un USB pasó por manos ajenas o la huella no coincide, reconstrúyelo.
- Si tu memoria tiene interruptor físico de escritura, no sirve aquí (el respaldo necesita escribir); la protección la dan la separación de particiones y la verificación por hash.
- En el PC técnico no edites ni "explores a fondo" HERRAMIENTAS: cualquier archivo nuevo (incluso un `desktop.ini`) hace fallar la verificación por "SOBRANTE". Los cambios legítimos se hacen solo con `Actualizar-Ancla.ps1`.

---

## 7. Cómo interpretar el reporte

Abre `RESPALDO:\Casos\<fecha>\Reporte\reporte.html` **en el PC sano**.

### 7.1 Veredicto

| Color | Significa | Qué hacer |
|---|---|---|
| **VERDE** | Sin detecciones, sin persistencia relevante, copia verificada | Analiza el respaldo con Defender y úsalo |
| **AMARILLO** | Revisar: archivos sin copiar o distintos, entradas de inicio "Media", sospechosos en cuarentena, firmas antiguas, disco con advertencias, o no hubo antivirus | Lee los motivos; normalmente el respaldo es usable tras revisarlo |
| **ROJO** | Malware detectado, persistencia "Alta", disco fallando, integridad del USB no confirmada o proceso interrumpido | No reutilices ese Windows; sigue las recomendaciones |

### 7.2 Secciones

- **Equipo y disco**: nombre del PC y versión (leídos del registro offline), modelo del disco, "Solo lectura confirmado: True" (debe decir True).
- **SMART**: `BUENO`, `DUDOSO` (sectores reasignados, desgaste ≥ 90 %, errores en el registro) o `MALO` (fallo predicho, sectores pendientes, errores no corregidos). Con MALO: clona el disco y reemplázalo.
- **chkdsk**: código 0 = sin errores; 2 = limpieza menor; 3 = errores (o no se pudo revisar). Si dice *"No se puede ejecutar sobre un volumen protegido contra escritura (esperado)"*, es la consecuencia normal del modo solo lectura: guíate por el estado *dirty* (`Volume - C: is Dirty` indica que Windows no se cerró bien o detectó corrupción). Solo **después** de tener el respaldo verificado repara con `chkdsk C: /f` desde el entorno de recuperación (eso sí escribe).
- **Malware y cuarentena**: cada fila tiene Id, severidad, ruta original, motivo (firma de ClamAV/Defender, heurística o persistencia) y SHA-256. Busca el hash en VirusTotal (sin subir el archivo) para una segunda opinión. Estados: `EN_CUARENTENA` (copia cifrada), `SOLO_REGISTRO` (demasiado grande, solo ruta y hash), `SOLO_REPORTE` (severidad media: se copió y se marca para revisión), `NO_ENCONTRADO`.
- **Persistencia**: puntuación sumada → `Alta` ≥ 4, `Media` 2-3, `Baja` 1. Suma puntos: ubicación típica de malware (Temp, raíz de AppData/ProgramData, Descargas, Escritorio) +3; AppData +2; fuera de rutas estándar +1; PowerShell codificado, descargas, mshta/regsvr32/certutil/bitsadmin +3; URL +2; ventana oculta +1; nombre de proceso del sistema fuera de System32 +3; doble extensión +3; archivo inexistente +1; Shell/Userinit modificados +4; tarea sin descriptor de seguridad (Tarrask) +4. Los archivos de entradas **Alta** se ponen en cuarentena (excepto binarios de Windows como powershell.exe). La columna *Firma digital*: `Valid` con un editor conocido tranquiliza; `NotSigned` en archivos de Windows es normal en WinPE (firma por catálogo), pero en un .exe de AppData es mala señal.
- **Respaldo**: resultado de robocopy por carpeta (bit 1 = copiados, 2 = extra, 4 = discrepancias, 8 = **no copiados tras reintentos**, 16 = error grave).
- **Verificación SHA-256**: debe tener `Diferentes = 0` y `Faltan = 0`. Filtra `verificacion.csv` por la columna *Resultado*:

| Resultado | Significado |
|---|---|
| `OK` | Copiado y hash idéntico al original |
| `DIFERENTE` | La copia no coincide: repítela |
| `FALTA_EN_DESTINO` | No se copió (ver robocopy_NN.log) |
| `ERROR_LECTURA_ORIGEN` | Sector dañado o archivo ilegible en el disco |
| `EXCLUIDO_CUARENTENA` | Marcado como sospechoso: está cifrado en Cuarentena |
| `SOLO_NUBE (...)` | Era un marcador de OneDrive: el contenido está en la nube, no en el disco |
| `EXCLUIDO_POR_CONFIGURACION` | Dentro de una carpeta excluida (p. ej. node_modules) |
| `CARPETA_NO_INCLUIDA` | Excluiste esa carpeta por falta de espacio |
| `EXCLUIDO_ENLACE` | Enlace simbólico: no se sigue (podría apuntar a otro disco o a un dispositivo) |
| `FUGA_CORREGIDA` | Un archivo marcado llegó a la copia; se cifró y retiró |

- **Integridad del USB**: "Al inicio" y "Al final" deben decir CORRECTA y la huella debe ser la tuya.
- **Errores**: lecturas fallidas, carpetas sin permiso, etc. Muchos errores de lectura en el mismo rango suelen indicar sectores dañados.
- **inventario_sha256.csv**: ruta, tamaño, fecha UTC, atributos y SHA-256 de cada archivo. Sirve para demostrar más adelante que un archivo no cambió (vuelve a calcular su hash y compáralo).

---

## 8. Problemas frecuentes

| Síntoma | Solución |
|---|---|
| "No se ve ningún disco interno" | Portátiles Intel recientes usan **VMD/RST**. Descarga el controlador "Intel RST VMD" del fabricante (carpeta con `.inf`) y reconstruye con `-Controladores`. Alternativa: en la UEFI cambia SATA a AHCI **solo durante el análisis** y vuelve a dejarlo como estaba. |
| Secure Boot Violation | Ver §4. |
| BitLocker bloqueado | Clave de recuperación desde account.microsoft.com/devices/recoverykey en otro equipo. Sin la clave, los datos no son recuperables. |
| "ClamAV o sus firmas no están disponibles" | Ejecuta `Actualizar-Firmas.ps1`. Si `clamscan --version` falla en WinPE, falta el runtime VC++ (reconstruye con el redistribuible instalado en el PC técnico). |
| ClamAV se cierra o va lentísimo | Poca RAM (< 6 GB). Usa `HashAlcance: SoloRespaldo` y considera Escanear-Con-Defender en un PC sano. |
| El teclado escribe otros símbolos | `startnet.cmd` fija teclado latinoamericano (`240a:0000080a`). Para EE. UU.: `wpeutil SetKeyboardLayout 0409:00000409` en la consola. |
| No cabe en el USB | El script te deja excluir carpetas. Libera casos antiguos de `Casos\` (tras guardarlos) o usa un USB mayor. |
| Integridad FALLIDA / análisis bloqueado | Si no cambiaste nada, no uses el USB: reconstrúyelo. Si cambiaste scripts, usa `Actualizar-Ancla.ps1`. |
| "No se encontró el USB con la firma ..." | El USB se reparticionó o Windows cambió su firma por coincidir con otro disco (muy raro). Reconstrúyelo. |
| Necesitas red en WinPE (no recomendado) | No está prevista: el análisis es 100 % sin conexión a propósito. |
| Volver al menú tras salir | En la consola: `powershell -NoProfile -ExecutionPolicy Bypass -File X:\Ancla\Iniciar.ps1` (o `INICIAR.bat` en HERRAMIENTAS). |

---

## 9. Segunda opinión con Microsoft Defender (opcional, recomendado si hay dudas)

*Microsoft Defender Offline* se lanza desde *Seguridad de Windows* y analiza el mismo PC desde el que se ejecuta; si ese Windows no arranca, no puedes usarlo. La alternativa equivalente:

1. Saca el disco del PC dañado y conéctalo a un PC sano con una caja/adaptador USB (SATA o NVMe).
2. En el PC sano, como administrador: `.\Escanear-Con-Defender.ps1`. Fija la política *OfflineAll* (para que Windows no monte el disco al conectarlo), pone el disco en **solo lectura**, actualiza Defender y ejecuta `MpCmdRun -Scan -ScanType 3 -File X:\ -DisableRemediation` (Defender solo informa: no limpia ni borra).
3. Las detecciones quedan en `RESPALDO:\Entrada\detecciones_externas.csv`. Al analizar con el USB, la fase 3 las importa y esos archivos van a cuarentena aunque ClamAV no los detecte.

ClamAV detecta menos amenazas que Defender en Windows; combinar ambos motores reduce mucho los falsos negativos.

---

## 10. Límites que conviene conocer

- Ningún antivirus detecta todo. Un resultado limpio reduce el riesgo, no lo elimina: por eso se re-analiza el respaldo con Defender antes de abrirlo.
- Los firmware rootkits (UEFI) y el malware solo en memoria quedan fuera del alcance de un análisis de disco.
- Las heurísticas y la puntuación de persistencia pueden marcar software legítimo (herramientas de desarrollo, lanzadores en AppData). Revisa antes de concluir.
- Archivos cifrados con contraseña (ZIP/RAR) no se pueden inspeccionar por dentro.
- Los archivos de OneDrive "solo en la nube" no están en el disco y no se pueden respaldar desde aquí.
