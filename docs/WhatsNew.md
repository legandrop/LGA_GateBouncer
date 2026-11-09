---
product: LGA GateBouncer
release_repo: legandrop/LGA_GateBouncer
tech_changelog: ChangeLog.md
version_heading: "v{v}:"
platforms: [win]
languages: [es, en]
en_from: "1.01"
---
# What's new in LGA GateBouncer
<!-- Editable while a version is unpublished. NOT append-only. Published versions are frozen. -->

## Unreleased

## v1.02
- [fixed] Un programa dentro de una carpeta de confianza ya no pide permiso para cada servidor nuevo cuando, además, tiene reglas para algunos servidores: los que no tienen regla los decide la carpeta.
  en: A program inside a trusted folder no longer asks for each new server when it also has rules for some servers: the folder decides the ones without a rule.

## v1.01
- [improved] Apps abre al instante, también la primera vez, y cambiar entre permitidas, bloqueadas y todas ya no se demora.
  en: Apps opens instantly, even the first time, and switching between allowed, blocked and all no longer lags.
- [improved] GateBouncer usa menos recursos mientras la ventana está cerrada y ocupa menos espacio en el disco.
  en: GateBouncer uses fewer resources while its window is closed and takes up less disk space.
- [improved] Con la app en castellano, el aviso de actualización y su ventana también están en castellano, y las novedades que muestra salen en el idioma que elegiste para GateBouncer.
  en: With the app in Spanish, the update notice and its window are in Spanish too, and the what's new list they show is in the language you chose for GateBouncer.
- [new] Settings suma Colors: seis paletas para la ventana y el aviso, que se aplican al instante y quedan guardadas.
  en: Settings adds Colors: six palettes for the window and the notice, applied instantly and remembered.
- [improved] Permitir tiene su propio verde en toda la ventana y en el aviso (botones, etiquetas de Apps y la sugerencia de la IA), como Bloquear tiene su rojo.
  en: Allow has its own green across the window and the notice (buttons, Apps tags and the AI suggestion), just like Block has its red.

## v1.00
- [new] Primera versión de LGA GateBouncer: un firewall por aplicación para Windows que avisa cuando un programa sin regla quiere conectarse a internet y deja elegir Allow o Block desde el mismo aviso.
- [new] Las reglas pueden valer para un archivo, para todas las versiones de una app o para todas las apps de una misma firma, por un rato o para siempre, y con «Trust a folder» para todo lo que se compila o instala en una carpeta.
- [new] Activity muestra cada intento bloqueado y cómo terminó, y Apps junta todas las reglas con un buscador y filtros.
- [new] El botón «Ask AI» del aviso explica qué es el programa y por qué se conecta, con una key propia de NVIDIA o Anthropic que se carga en Settings.
- [new] Settings tiene zoom (110 % de fábrica), idioma inglés o castellano y búsqueda de actualizaciones al iniciar: las versiones nuevas se instalan desde la misma app.
