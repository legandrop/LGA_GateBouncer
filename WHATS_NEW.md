# What's new in LGA GateBouncer

## v1.02 (2026-11-09)

- **New:** Settings adds Rules: Export rules saves your rules to a file, complete as a backup before reinstalling Windows or only the portable ones to share with someone else, and Import rules adds them showing first what comes in and what clashes with yours.
- **New:** Clean up rules suggests removing rules for programs and folders that are gone, and for installers and apps that have not tried to connect in a long time, with an automatic backup before removing.
- **Improved:** A rule for a program that is not installed yet applies by itself when the program appears.
- **Fixed:** A program inside a trusted folder no longer asks for each new server when it also has rules for some servers: the folder decides the ones without a rule.

## v1.01 (2026-11-08)

- **New:** Settings adds Colors: six palettes for the window and the notice, applied instantly and remembered.
- **Improved:** Apps opens instantly, even the first time, and switching between allowed, blocked and all no longer lags.
- **Improved:** GateBouncer uses fewer resources while its window is closed and takes up less disk space.
- **Improved:** With the app in Spanish, the update notice and its window are in Spanish too, and the what's new list they show is in the language you chose for GateBouncer.
- **Improved:** Allow has its own green across the window and the notice (buttons, Apps tags and the AI suggestion), just like Block has its red.

## v1.00 (2026-11-08)

- **New:** Primera versión de LGA GateBouncer: un firewall por aplicación para Windows que avisa cuando un programa sin regla quiere conectarse a internet y deja elegir Allow o Block desde el mismo aviso.
- **New:** Las reglas pueden valer para un archivo, para todas las versiones de una app o para todas las apps de una misma firma, por un rato o para siempre, y con «Trust a folder» para todo lo que se compila o instala en una carpeta.
- **New:** Activity muestra cada intento bloqueado y cómo terminó, y Apps junta todas las reglas con un buscador y filtros.
- **New:** El botón «Ask AI» del aviso explica qué es el programa y por qué se conecta, con una key propia de NVIDIA o Anthropic que se carga en Settings.
- **New:** Settings tiene zoom (110 % de fábrica), idioma inglés o castellano y búsqueda de actualizaciones al iniciar: las versiones nuevas se instalan desde la misma app.
