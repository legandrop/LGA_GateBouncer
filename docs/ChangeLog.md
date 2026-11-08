# ChangeLog de LGA GateBouncer

v1.01:
- Apps tardaba 1,5 s la primera vez y ~200 ms por filtro: armaba un widget por fila y le pedía a Windows el ícono de
  cada programa en el hilo de la interfaz. Ahora un delegado pinta las filas, los íconos llegan desde un hilo propio
  con caché (`AppIcons`) y los filtros se crean una sola vez: 42 ms la primera entrada y ~10 ms por filtro.
- Menos consumo en segundo plano: reglas e historial se piden al motor seguido solo mientras se ven (`setRefresh`),
  las entradas de Apps se recalculan solo si cambian las reglas y el registro del aviso queda tras
  `GATEBOUNCER_TOAST_TRACE`. El paquete deja de llevar plugins de imagen, SVG y táctiles que no se usan (-1,5 MB).
- El updater (`libs/lgaupdate` rev 4) habla en el idioma de la app. La versión ya no se sube en cada cambio:
  `bump_version.bat` la sube al publicar, como en Mighty Tools. Logo de la barra a 20 px.
- Base para paletas de color: los colores seguían fijos en `theme.h` y en las hojas de estilo. Ahora `src/palette.*`
  los agrupa en 17 roles con un color base cada uno (fondos, bordes, títulos, rótulos del índice, cuatro niveles de
  texto, acento, interruptores, estados) y deriva los demás tonos en HSL; `Theme::css`/`Theme::color` traducen y la
  ventana se rearma en vivo. Editor sólo de desarrollo (`GATEBOUNCER_PALETTE_EDITOR=1`) y paletas de prueba en
  `resources/palettes/`.
- Permitir usaba el cian de «funciona» (etiquetas) o el violeta del botón principal (botones). Ahora tiene su verde
  (`kAllow*`, rol `allow`) en etiquetas, sugerencia de IA y botones Allow, que pasan al estilo de Block.
- Las novedades del aviso de update salían siempre en castellano, aunque la ventana estuviera en inglés. Ahora
  `libs/lgaupdate` es la rev 5 (`LgaWhatsNew::displayText()` elige el `text_en` de cada ítem si la app está en inglés)
  y `docs/WhatsNew.md` es bilingüe desde la v1.01 (`languages: [es, en]`, una línea `en:` por ítem).

v1.00:
- Primera versión publicada. El firewall es `GateBouncerEngine.exe`, un servicio que filtra con WFP en modo usuario:
  el primer intento de un programa sin regla se bloquea y avisa, y la decisión vale para el siguiente intento. La
  ventana (`GateBouncer.exe`) tiene el diseño de Mighty Tools en violeta LGA.
- Settings suma la tarjeta App: buscar actualizaciones al iniciar (biblioteca común `libs/lgaupdate`, manifiesto de
  `legandrop/LGA_Updates`), idioma inglés/castellano (`src/i18n*`, tabla controlada por `tools/qa/check_i18n.ps1`) y
  zoom 100/110/120 % por `QT_SCALE_FACTOR`, 110 % de fábrica; cambiar zoom o idioma reinicia la ventana.
- La versión sale de `project(... VERSION)` de CMakeLists.txt; `instalador.bat` la pasa al instalador y `publicar.ps1`
  publica el release.
