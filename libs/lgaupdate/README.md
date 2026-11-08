# lgaupdate — auto-update de las apps LGA

**Pieza canónica de `LGA_Base_QT_C_Py`, rev 5 (2026-11-08).** Cada app la copia **idéntica** a su
`libs/lgaupdate`, este README incluido, y no la edita: un cambio se hace acá, se sube la revisión
y se vuelve a copiar a todas. Así comparar una copia con la canónica es un `diff -r` sin
excepciones.

```bash
rsync -a --delete ../LGA_Base_QT_C_Py/libs/lgaupdate/ libs/lgaupdate/
diff -r ../LGA_Base_QT_C_Py/libs/lgaupdate libs/lgaupdate && echo identica
```

La usan FrameRev, Media Tools (con el Shot Player), Theta Explorer, Video Downloader y GateBouncer. La rev 2
existe para que FileManager S3 y PipeSync, que tenían su propio `FM_UpdateService` (del que esta
biblioteca es un port), se muden a ella sin perder nada. `LGAUPDATE_REVISION` (en `LgaUpdateService.h`) dice qué revisión trae una
copia: una app que necesita algo nuevo la exige con `#if LGAUPDATE_REVISION < N` / `#error`.

## Qué hace

Chequeo contra el manifiesto `legandrop.github.io/LGA_Updates/versions.json` (nunca contra la API
de GitHub), cartel "Update Available" con notas (Update now / Remind me later / Skip this version /
Cancel), descarga por streaming con SHA-256 del manifiesto (fail-closed: sin hash no se ofrece),
y un helper que espera a que la app se cierre:

- **Windows**: baja `<productId>_Setup_v<x>.exe` y lo abre con su wizard. Si sigue abierta otra
  ventana de la app, **posterga** el update con un aviso (en macOS, una notificación); con
  `closePolicy = Force` la cierra a la fuerza, junto con sus procesos de fondo.
- **macOS**: baja `<productId>_Mac_v<x>.zip`, lo extrae con `ditto`, corre `codesign --verify
  --deep --strict`, reemplaza el bundle instalado (con rollback) y reabre la app. El bundle se
  busca por glob dentro del ZIP: el nombre del `.app` no tiene que coincidir con `productId`,
  pero el bundle instalado no se renombra (el helper reemplaza el que está corriendo). El helper
  deja en el log cada paso y, si falla, qué comando falló; el `.zip` se borra siempre al terminar.

Además: chequeo periódico por reloj de pared (3 h ± 15 min), "What's new" una vez después de
instalar, historial completo a pedido, y barrido de la carpeta de descargas
(`sweepUpdateCache`).

## Contrato con la app (`LgaUpdateConfig`)

| Campo | Para qué |
|---|---|
| `productId`, `displayName`, `releaseRepoSlug`, `windowsExecutableName` | Identidad del asset, nombre visible, repo de releases (clave en el manifiesto) y exe que el helper espera en Windows |
| `settingsPath`, `updateCacheDir` | `.ini` de la app (`Updates/*`) y carpeta de descargas (en Windows, dentro de la instalación; en macOS, fuera del bundle) |
| `presentDialog` | **Los carteles**. La biblioteca arma un `LgaUpdateDialogSpec` (tipo, título, mensaje HTML, notas, detalle, botones con rol) y la app lo dibuja con sus propios diálogos. Sin él cae a un `QMessageBox` |
| `emphasizeHtml` | Cómo se resalta un dato en el mensaje (default `<b>`) |
| `updateBlockedReason` | Por qué este binario no se actualiza (árbol de desarrollo) |
| `installBlockedReason` | Por qué no se puede instalar ahora (trabajo sin guardar, descargas en curso). Se reevalúa al elegir Update now y al terminar la descarga |
| `prepareForUpdatePrompt`, `quitApplication` | Preparar la UI antes del cartel; camino de cierre propio |
| `relaunchWhenUpdatePostponed` | Si el helper posterga porque otra instancia sigue abierta, reabrir la que se cerró (una residente como FrameRev). Default false |
| `automaticChecksEnabled`, `networkFactory`, `busyCursorOnManualCheck` | Preferencia del usuario, red de prueba, cursor de espera para apps sin botón "Checking..." |

### Rev 2: lo que trajo de `FM_UpdateService` (todo opt-in)

Con los defaults, una app de la rev 1 se comporta igual: solo re-copia.

| Campo | Para qué | Default |
|---|---|---|
| `edition`, `whatsNewAudiences` | Filtrar las notas por edición (`[studio]`/`[client]`) y por audiencia (`[for:]`). Las audiencias se leen al presentar | Sin filtro |
| `settingsKeys`, `legacySettingsKeys` | Claves del estado en el `.ini`. Las anteriores se leen si la actual no existe (y "Update now" borra las dos): una app que viene de otro updater no pierde el skip, el snooze ni, sobre todo, el "What's new" del update que la migra | `Updates/*`, sin anteriores |
| `updateLogPath` | Log de la app (chequeo, descarga, helper, con rotación a 1 MB); el mismo archivo donde escribe el helper. Los carteles de error llevan su ruta en Details | Sin log de la app; el helper de macOS escribe en `~/Library/Logs/LGA/<productId>/Update.log` |
| `closePolicy` | `Postpone` o `Force`: qué hace el helper si la app sigue abierta pasado el plazo (15 s en Windows, 30 s en macOS) | `Postpone` |
| `windowsPythonProcessNames`, `windowsRedisCommandLineMatches`, `windowsPythonCommandLineMatches`, `macBackendProcessPatterns` | Procesos de fondo que el helper espera (Windows: 8 s, y después los cierra o posterga según `closePolicy`; macOS: 20 s, y solo lo anota) | Ninguno |
| `progressDialogStyleSheet` | Hoja de estilo del diálogo de progreso de la descarga (objectName `updateDownloadProgressDialog`) | El estilo de la app |
| `updateDirWriteFallback` | Si la carpeta de `updateCacheDir` no acepta una escritura real, bajar al `CacheLocation` o `TempLocation` del usuario | Falla como antes |

Además, sin config: un manifiesto de schema más nuevo pide reinstalar ("This version is too old to
read the update list") en vez de un fallo genérico; la descarga también se rechaza sin SHA-256
(segunda llave del fail-closed); y los barridos de las carpetas del usuario tocan solo
`<productId>_Mac_v*`, `<productId>_Setup_v*` y `<productId>_Update_Helper_*`.

Cambios de los helpers que valen para todas las apps, también sin config:

- **Windows**: si `Start-Process` del instalador falla, el helper ahora reintenta de verdad (20
  veces cada 0,5 s) y sale con 2 si no pudo. En la rev 1 el error se tragaba y salía con 0 sin
  lanzar nada.
- **macOS**: el helper escribe siempre su log (los pasos, el entorno, qué comando falló y en qué
  paso), en `updateLogPath` o, sin él, en `~/Library/Logs/LGA/<productId>/Update.log`, unas 15
  líneas por update. Ese archivo solo rota cuando la app fija `updateLogPath`. El `.zip` se borra
  siempre al terminar, también si el update falla o se posterga.
- Los procesos de fondo de macOS se buscan sin contar al propio helper, cuya línea de comandos
  lleva el path del `.app` y del `.zip`.

`LgaUpdateDialogSpec` suma `version` (la ofrecida en el cartel de update, la instalada en el
"What's new" de después de instalar), para el presentador que arma su propio texto.

`LgaWhatsNew` suma `headline()` (el primer ítem visible, para avisos de una línea) y los
parámetros opcionales `edition` y `audiences` de `range()` y `filtered()`.

Señales: `checkStarted` / `checkFinished` (para un botón "Check now"), y `updateAvailable(version)`
para un aviso que no interrumpe (sale aunque el usuario haya pospuesto el cartel).

El presentador decide por `spec.kind` y por el **rol** de cada botón, no por su posición: cada app
ordena los botones a su manera y el servicio interpreta el rol del elegido.

### Rev 3: reintentos de red (sin config)

Regla de LGA (`LGA_RepoTools/Docs/Convencion_Red_Reintentos.md`): un pedido que falla por
conexión (rechazada, cortada, timeout, DNS), por un corte de HTTP/2 o con 408/429/5xx se vuelve a
mandar **3 veces, con 5 s entre intentos**; un 4xx definitivo no. Motivo: GateBouncer, el firewall
por aplicación de la PC de trabajo, bloquea el primer intento de cada programa y de cada destino
nuevo. Vale para el chequeo, el manifiesto de las notas, las notas y la descarga. Qué se reintenta
y cuánto se espera lo decide `include/lgaupdate/LgaNetRetry.h`, que las apps sin lgaupdate copian
idéntico.

- La cuenta es **por servidor** (`LgaNetRetry::Budget`): las notas y el instalador salen de
  github.com y siguen un redirect al servidor de los archivos, y cada uno puede quedar bloqueado
  en su primer intento. Cada servidor donde el pedido falla tiene sus 3 reintentos, con un tope de
  10 intentos en total.

- La espera es un `QTimer::singleShot` con contexto, nunca un hilo dormido. La cortan el Cancel de
  la descarga, `LgaWhatsNewFetcher::cancel()`, la destrucción del servicio y `aboutToQuit`.
- Cada intento va al log de updates («intento 1 de 4», después «intento 3 (2 de 4 en
  &lt;servidor&gt;)»); sin `updateLogPath`, a `qInfo`. El fetcher recibe el suyo en `Request::log`.
- El chequeo sigue siendo una sola fase (`checkStarted` y `checkFinished` una vez) y cuenta como
  ocupado mientras espera. El reintento largo del periódico (`periodicCheckRetryMs`) va después de
  los cuatro intentos.
- La descarga reanuda por `Range` desde donde quedó (desde cero si no llegó nada; si el servidor
  ignora el `Range` y manda 200, empieza de nuevo). Los cortes de una misma descarga suman en la
  misma cuenta: no vuelve a empezar porque el intento anterior haya traído datos. Durante la espera
  el diálogo de progreso dice «Connection problem. Retrying (attempt 2 of 4)...», con el número del
  servidor que falló.
- `checkTimeoutMs` y `downloadTimeoutMs` valen por intento: un chequeo con timeouts puede tardar
  4 × 15 s + 3 × 5 s. Una prueba de la app que simula fallos de red baja la espera con
  `LgaNetRetry::delayMsOverrideForTests()`.

**Banco de pruebas** (`tests/`, apagado por defecto): el servicio y el fetcher reales contra
servidores propios en 127.0.0.1 (HTTP/1.1, HTTP/2 sin TLS para los cortes por RST_STREAM y GOAWAY,
y un proxy de prueba para los redirects de github.com), sin red y sin instalar nada. Se compila
fuera del repo y se
corre solo con el runner de QA:

```powershell
cmake -S <repo> -B <carpeta fuera del repo> -G Ninja -DLGAUPDATE_BUILD_TESTS=ON
cmake --build <carpeta> --target lgaupdate_retry_tests
powershell -NoProfile -ExecutionPolicy Bypass -File <Base>\tools\qa\run_headless.ps1 `
    -Exe <carpeta>\lgaupdate_tests\lgaupdate_retry_tests.exe -Arguments '<carpeta de trabajo nueva>' -TimeoutSec 240
```

### Rev 4: textos en inglés o castellano (`language`)

Hasta la rev 3 los carteles salían siempre en inglés, aunque la app estuviera en castellano.
Ahora la app pide el idioma con `LgaUpdateConfig::language`: `"es"` pasa a castellano los
carteles, el diálogo de la descarga, los rótulos de las notas (NUEVO, MEJORADO, CORREGIDO) y los
avisos que muestra el helper; vacío (default) o cualquier otro valor deja el inglés, así que una
app que solo re-copia se ve igual. Las notas de cada versión no se traducen acá: vienen escritas en
el `WhatsNew.md` del producto (desde la rev 5, también en inglés en las apps bilingües).

- `LgaUpdateI18n.h` / `src/LgaUpdateI18n.cpp`: la tabla en castellano vive en el código (sin
  `.qm`) y un `QTranslator` propio la instala el constructor del servicio. Solo contesta los
  contextos de la biblioteca (`LgaUpdateService`, `LgaWhatsNew`): no pisa los traductores de la
  app. El idioma vale para todo el proceso; cambiarlo es crear el servicio con otro `language`.
- Los avisos del helper (otra ventana abierta, procesos de fondo, update fallido en macOS) dejan
  de estar fijos en el script: los arma la app con `tr()` y se insertan escapados. El `.ps1` del
  helper de Windows se escribe con BOM, para que PowerShell 5.1 lea bien los acentos.
- `tests/check_i18n.ps1` confronta la tabla con los `tr()`: al agregar un texto, correrlo. Sale 1
  si falta una traducción o sobra una clave.
- Estilo de las traducciones: el de las apps LGA en castellano (infinitivo o impersonal, nunca vos
  ni tú). Las letras de los atajos no cambian (las fija el código): «Act&ualizar ahora» sigue en U.

### Rev 5: las notas en el idioma de la app (`text_en`)

En una app bilingüe (GateBouncer, por ejemplo) con la interfaz en inglés, las notas de cada
versión salían en castellano, que es el texto base de todo `WhatsNew.md`. Ahora un producto puede
declararse bilingüe (`languages: [es, en]` en la cabecera de su `WhatsNew.md`) y escribir cada
ítem también en inglés; `build_whats_new.py` de `LGA_RepoTools` lo publica en el campo opcional
`text_en` de cada ítem de `whats_new.json`.

- `LgaWhatsNew::Item::textEn` guarda ese texto (vacío si no viene). Un `text_en` que no es texto
  invalida el JSON entero, como cualquier otro campo mal formado.
- `LgaWhatsNew::displayText()` elige: el inglés si el updater está en inglés
  (`LgaUpdateI18n::language()`) y el ítem lo trae; si no, el castellano. Lo usan `headline()` y
  `toHtml()`, o sea el cartel de update, el aviso de después de instalar y el historial.
- Sin cambios para nadie más: un producto monolingüe no trae `text_en`, y una app en castellano
  sigue mostrando `text`. Los lectores viejos (rev ≤ 4 y `FM_WhatsNew` de FileManager S3)
  ignoran el campo.
- `tests/TestLgaWhatsNewLanguage.cpp` (`lgaupdate_language_tests`): parseo y elección del idioma,
  sin red ni ventanas, con el mismo runner que el banco de reintentos.

## Historia

Antes de la rev 1 había tres copias que ya diferían: la de Theta Explorer (la más nueva), la de
FrameRev (igual en lógica, con el cartel de `Dialogs` adentro) y la de Media Tools (la más vieja:
carteles propios dentro de la biblioteca, sin `installBlockedReason` y con cierre forzado de la app
en el helper). La rev 1 parte de la de Theta Explorer (`e1547cb`), saca el cartel de la app a
`presentDialog`, y suma `emphasizeHtml` (FrameRev), `busyCursorOnManualCheck` (Media Tools) y
`updateAvailable` (Video Downloader). Cada app conserva sus carteles: Theta Explorer y Video
Downloader traducen la spec a su `ConfirmDialog`, FrameRev a `Dialogs` (`UpdateDialogPresenter`) y
Media Tools a `libs/lgaupdateui`, que antes vivía adentro de la biblioteca.

La rev 2 absorbe lo que `FM_UpdateService` tenía y esta no —log de updates, diagnóstico del helper
de macOS, cierre forzado con procesos de fondo, fallback de carpeta, notas por edición y audiencia,
mensaje de schema nuevo— como opciones, para que FileManager S3 y PipeSync se muden sin perder nada
y las demás apps sigan igual. Los tests viven en FrameRev (`tests/TestLgaUpdateService.cpp`, con
red simulada, y `tests/TestLgaWhatsNew.cpp`, con los casos de ediciones y audiencias que venían de
`FM_WhatsNewTest`).

La rev 3 suma los reintentos de red de la regla de LGA y su banco de pruebas propio, en `tests/`.

La rev 4 suma el idioma: la app pide inglés o castellano con `language` y la biblioteca trae su tabla en castellano. Salió de GateBouncer, que tiene la interfaz en los dos idiomas y mostraba el updater en inglés.
