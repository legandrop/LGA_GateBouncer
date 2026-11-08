# ChangeLog de LGA GateBouncer

v1.00:
- Primera versión publicada. El firewall es `GateBouncerEngine.exe`, un servicio que filtra con WFP en modo usuario:
  el primer intento de un programa sin regla se bloquea y avisa, y la decisión vale para el siguiente intento. La
  ventana (`GateBouncer.exe`) tiene el diseño de Mighty Tools en violeta LGA.
- Settings suma la tarjeta App: buscar actualizaciones al iniciar (biblioteca común `libs/lgaupdate`, manifiesto de
  `legandrop/LGA_Updates`), idioma inglés/castellano (`src/i18n*`, tabla controlada por `tools/qa/check_i18n.ps1`) y
  zoom 100/110/120 % por `QT_SCALE_FACTOR`, 110 % de fábrica; cambiar zoom o idioma reinicia la ventana.
- La versión sale de `project(... VERSION)` de CMakeLists.txt; `instalador.bat` la pasa al instalador y `publicar.ps1`
  publica el release.
