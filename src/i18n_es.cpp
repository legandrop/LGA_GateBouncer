#include "i18n.h"

// Tabla inglés -> español de la interfaz (ver i18n.h). La clave es el texto en inglés EXACTO del código, con sus
// placeholders; la traducción conserva los mismos %1, %2. "contexto|texto" es la clave de I18n::trc. Agrupada por
// pantalla.
// Lo que no está acá queda en inglés a propósito: el nombre de la app, nombres de programas, archivos, carpetas y
// servidores, lo que escribe el motor (sus errores y el historial «Rule saved: …»; las confirmaciones de cada comando las
// arma la ventana y sí se traducen), las respuestas de la IA y el catálogo de apps conocidas. Los textos del updater
// (libs/lgaupdate) traen su propia tabla en castellano: la ventana le pasa el idioma (LgaUpdateConfig::language).
// Estilo, como Mighty Tools: infinitivo o impersonal, nunca vos ni tú. Vocabulario fijo: Protection -> Protección,
// Requests -> Pedidos, Apps -> Apps, Activity -> Actividad, Settings -> Ajustes, Allow -> Permitir, Block -> Bloquear,
// How it works -> Cómo funciona, rule -> regla (una Block rule es una «regla de bloqueo»), notice -> aviso,
// engine -> motor, Trust a folder -> Confiar en una carpeta. Un nombre de opción citado dentro de otra oración se cita
// con su texto traducido, el mismo que se ve.
// tools\qa\check_i18n.ps1 confronta esta tabla con los I18n::tr / trc del código.

#define E(en, es) {QStringLiteral(en), QStringLiteral(es)}

namespace Gate::I18n {

const QHash<QString, QString> &spanishTable() {
    static const QHash<QString, QString> table = {
        // ---------- Comunes: decisiones, reglas y opciones de la regla (ventana y aviso)
        E("Allow", "Permitir"),
        E("Block", "Bloquear"),
        E("Cancel", "Cancelar"),
        E("Remove", "Quitar"),
        E("Rule", "Regla"),
        E("Wants", "Quiere ir a"),
        E("Started by", "Lanzado por"),
        E("Not signed", "Sin firma"),
        E("Apply to", "Se aplica a"),
        E("For", "Durante"),
        E("Destination", "Destino"),
        E("Always", "Siempre"),
        E("1 minute", "1 minuto"),
        E("%1 minutes", "%1 minutos"),
        E("1 hour", "1 hora"),
        E("%1 hours", "%1 horas"),

        // ---------- Confirmaciones de cada decisión (las arma la ventana al mandar el comando al motor)
        E("any version of %1 from %2", "cualquier versión de %1 de %2"),
        E("all apps from %1", "todas las apps de %1"),
        E("all apps", "todas las apps"),
        E("%1 to %2", "%1 hacia %2"),
        E(" until restart", " hasta reiniciar"),
        E(" for %1", " durante %1"),
        E("Allow%1 saved for %2. The next connection attempt uses this rule.",
          "Se guardó Permitir%1 para %2. El próximo intento de conexión usa esta regla."),
        E("Block%1 saved for %2. The next connection attempt uses this rule.",
          "Se guardó Bloquear%1 para %2. El próximo intento de conexión usa esta regla."),
        E("Every program in %1 can connect%2, also new builds there.",
          "Todos los programas de %1 pueden conectarse%2, también los builds nuevos de ahí."),
        E("Every program in %1 stays blocked%2.", "Todos los programas de %1 siguen bloqueados%2."),
        E("%1 in %2 can connect%3, also new builds there.",
          "%1 en %2 puede conectarse%3, también los builds nuevos de ahí."),
        E("%1 in %2 stays blocked%3.", "%1 en %2 sigue bloqueado%3."),
        E("Rule removed for %1. The next connection will be blocked and ask again.",
          "Se quitó la regla de %1. La próxima conexión se bloquea y vuelve a preguntar."),
        E("Local network connections no longer ask.", "Las conexiones de la red local ya no preguntan."),
        E("Local network connections ask like any other.", "Las conexiones de la red local preguntan como cualquier otra."),
        E("Unknown applications can connect. Saved rules still apply.",
          "Las apps desconocidas pueden conectarse. Las reglas guardadas siguen valiendo."),
        E("GateBouncer engine is not running. Nothing was changed.",
          "El motor de GateBouncer no está funcionando. No se cambió nada."),
        E("No reply", "Sin respuesta"),
        E("Until restart", "Hasta reiniciar"),
        E("Until %1", "Hasta %1"),
        E("Any destination", "Cualquier destino"),
        E("Only %1", "Solo %1"),
        E("Any destination (whole app)", "Cualquier destino (toda la app)"),
        E("This app, any version", "Esta app, cualquier versión"),
        E("This file only", "Solo este archivo"),
        E("All apps from %1", "Todas las apps de %1"),
        E("This app in %1", "Esta app en %1"),
        E("Covers %1 in %2 and its subfolders, also new builds.",
          "Cubre %1 en %2 y sus subcarpetas, también los builds nuevos."),
        E("Covers every program in %1 and its subfolders, also ones built there later.",
          "Cubre todos los programas de %1 y sus subcarpetas, también los que se compilen ahí más adelante."),
        E("No signature: the rule can't follow a publisher, only this file or this app's name inside its repository.",
          "Sin firma: la regla no puede seguir a un editor, solo a este archivo o al nombre de esta app dentro de su "
          "repositorio."),
        E("No signature: a rule can only cover this exact file. If the file changes, it asks again.",
          "Sin firma: una regla solo puede cubrir este archivo exacto. Si el archivo cambia, vuelve a preguntar."),
        E("1 attempt", "1 intento"),
        E("%1 attempts", "%1 intentos"),
        E("This PC", "Esta PC"),
        E("Local network", "Red local"),
        E("protocol|Unknown", "Desconocido"),
        E("no server name seen", "sin nombre de servidor"),
        E("%1 · no server name seen", "%1 · sin nombre de servidor"),

        // ---------- Explicaciones con IA (ventana y aviso)
        E("AI suggests Block", "La IA sugiere Bloquear"),
        E("AI suggests Allow", "La IA sugiere Permitir"),
        E("AI: your call", "IA: sin preferencia"),
        E("WHY IT CONNECTS", "POR QUÉ SE CONECTA"),
        E("WHY THIS SUGGESTION", "POR QUÉ ESTA SUGERENCIA"),
        E("IS IT GENUINE", "¿ES LEGÍTIMO?"),
        E("Asking the AI what this is…", "Preguntando a la IA qué es…"),
        E("Asking %1 what this is…", "Preguntando a %1 qué es…"),
        E("Explanations are off.", "Las explicaciones están apagadas."),
        E("The explanation did not arrive.", "La explicación no llegó."),
        E("What is this program?", "¿Qué es este programa?"),
        E("Try again", "Reintentar"),
        E("Ask AI", "Preguntar a la IA"),
        E("Set up in Settings", "Configurar en Ajustes"),
        E("Asking AI…", "Preguntando a la IA…"),
        E("Not explained yet", "Sin explicar todavía"),
        E("AI explanation · %1 · may be wrong", "Explicación de IA · %1 · puede equivocarse"),
        E("AI explanation · %1 · may be wrong and never decides for you",
          "Explicación de IA · %1 · puede equivocarse y nunca decide sola"),
        E("You can decide now; the answer never holds the notice.",
          "Se puede decidir ya; la respuesta nunca retiene el aviso."),
        E("You can decide now; the answer never holds the request.",
          "Se puede decidir ya; la respuesta nunca retiene el pedido."),
        E("Automatic explanations are off.", "Las explicaciones automáticas están apagadas."),

        // ---------- Aviso
        E("Access request", "Pedido de acceso"),
        E("More actions", "Más acciones"),
        E("Close and keep it waiting", "Cerrar y dejarlo en espera"),
        E("Open GateBouncer", "Abrir GateBouncer"),
        E("Pending list", "Lista de pedidos"),
        E("Allow or Block applies to this server only. Choose <b style=\"color:%1\">Any destination (whole app)</b> in "
          "the menu to replace its server rules.",
          "Permitir o Bloquear vale solo para este servidor. Elegir <b style=\"color:%1\">Cualquier destino (toda la "
          "app)</b> en el menú para reemplazar sus reglas por servidor."),
        E("Signature", "Firma"),
        E("Details", "Detalles"),
        E("Less", "Menos"),
        E("Blocked. Allow lets its next attempt connect.", "Bloqueado. Permitir deja conectar su próximo intento."),
        E("Blocked: a new server. %1 already has rules for 1 server.",
          "Bloqueado: un servidor nuevo. %1 ya tiene reglas para 1 servidor."),
        E("Blocked: a new server. %1 already has rules for %2 servers.",
          "Bloqueado: un servidor nuevo. %1 ya tiene reglas para %2 servidores."),
        E("Blocked: a new server for %1.", "Bloqueado: un servidor nuevo para %1."),
        E("<span style=\"color:%1; font-weight:500\">%2</span> · valid",
          "<span style=\"color:%1; font-weight:500\">%2</span> · válida"),
        E("1 more waiting", "1 más en espera"),
        E("%1 more waiting", "%1 más en espera"),
        E("read only", "solo lectura"),

        // ---------- Ventana: barra, índice y Cómo funciona
        E("How it works", "Cómo funciona"),
        E("Opens and closes How it works on every page.", "Abre y cierra Cómo funciona en todas las páginas."),
        E("Minimize", "Minimizar"),
        E("Maximize or restore", "Maximizar o restaurar"),
        E("Close to the tray", "Cerrar a la bandeja"),
        E("Protection", "Protección"),
        E("Firewall", "Firewall"),
        E("Requests", "Pedidos"),
        E("Apps", "Apps"),
        E("Activity", "Actividad"),
        E("Settings", "Ajustes"),
        E("1 step", "1 paso"),
        E("%1 steps", "%1 pasos"),
        E("Engine not running", "Motor detenido"),
        E("On · not asking", "Sin preguntar"),
        E("Test session", "Sesión de prueba"),
        E("On · asking first", "Pregunta antes"),
        E("Nothing waiting", "Nada en espera"),
        E("Oldest %1", "El más antiguo: %1"),
        E("1 app", "1 app"),
        E("%1 apps", "%1 apps"),
        E("%1 · 1 temporary", "%1 · 1 temporal"),
        E("%1 · %2 temporary", "%1 · %2 temporales"),
        E("1 blocked since %1", "1 bloqueo desde %1"),
        E("%1 blocked since %2", "%1 bloqueos desde %2"),
        E("1 blocked", "1 bloqueo"),
        E("%1 blocked", "%1 bloqueos"),
        E("AI: %1", "IA: %1"),
        E("AI explanations off", "Explicaciones con IA apagadas"),

        // ---------- Confiar en una carpeta (diálogo) y problemas de una carpeta (los textos del motor)
        E("Trust a folder", "Confiar en una carpeta"),
        E("The rule covers one program name, or every program, inside the folder and its subfolders, also builds made "
          "or copied there later. A rule for a file, an app or a publisher comes first. Trust only folders where you "
          "build or install programs yourself: whatever is saved there with that name gets the same access.",
          "La regla cubre un nombre de programa, o todos los programas, dentro de la carpeta y sus subcarpetas, también "
          "los builds que se hagan o se copien ahí más adelante. Una regla de un archivo, una app o un editor va "
          "primero. Confiar solo en carpetas donde uno mismo compila o instala programas: lo que se guarde ahí con ese "
          "nombre recibe el mismo acceso."),
        E("Folder", "Carpeta"),
        E("Browse…", "Examinar…"),
        E("Program name (optional)", "Nombre del programa (opcional)"),
        E("Every program, or one name such as MyApp.exe", "Todos los programas, o un nombre como MyApp.exe"),
        E("Choose the folder of a project or an app.", "Elegir la carpeta de un proyecto o de una app."),
        E("Use a file name such as MyApp.exe, or leave it empty for every program.",
          "Usar un nombre de archivo como MyApp.exe, o dejarlo vacío para todos los programas."),
        E("✓ Every program in %1 and its subfolders.", "✓ Todos los programas de %1 y sus subcarpetas."),
        E("✓ %1 in %2 and its subfolders.", "✓ %1 en %2 y sus subcarpetas."),
        E("Choose the folder to trust", "Elegir la carpeta de confianza"),
        E("Choose a folder.", "Elegir una carpeta."),
        E("This is not a valid folder path.", "No es una ruta de carpeta válida."),
        E("Choose a folder on a local drive, such as C:\\Projects\\MyApp.",
          "Elegir una carpeta de un disco local, como C:\\Projects\\MyApp."),
        E("A whole drive cannot be trusted. Choose a folder inside it.",
          "No se puede confiar en un disco entero. Elegir una carpeta dentro de él."),
        E("Choose a folder on a local drive: not a network, removable or optical drive.",
          "Elegir una carpeta de un disco local: no de red, extraíble ni óptico."),
        E("%1 cannot be trusted, nor anything inside it.", "No se puede confiar en %1 ni en nada de lo que contiene."),
        // Rótulos de carpetas protegidas que el motor da en inglés (van dentro de las oraciones de arriba).
        E("folder|A user profile", "un perfil de usuario"),
        E("folder|The Recycle Bin", "la Papelera de reciclaje"),
        E("folder|Desktop", "Escritorio"),
        E("folder|Documents", "Documentos"),
        E("folder|Downloads", "Descargas"),
        E("%1 cannot be trusted as a whole. Choose a folder inside it.",
          "No se puede confiar en toda la carpeta %1. Elegir una carpeta dentro de ella."),
        E("This folder does not exist.", "Esta carpeta no existe."),
        E("This is a file, not a folder.", "Es un archivo, no una carpeta."),
        E("This folder is on a drive mounted inside another folder. Use a drive letter for that drive instead.",
          "Esta carpeta está en un disco montado dentro de otra carpeta. Usar una letra de unidad para ese disco."),
        E("Folders inside %1 cannot be trusted.", "No se puede confiar en carpetas dentro de %1."),
        E("This folder is a link to %1. Trust the real folder instead.",
          "Esta carpeta es un enlace a %1. Confiar en la carpeta real."),
        E("This folder holds %1, which cannot be trusted.", "Esta carpeta contiene %1, en la que no se puede confiar."),

        // ---------- Protección
        E("Ask before unknown applications connect", "Preguntar antes de que se conecten apps desconocidas"),
        E("Without the engine, new applications cannot ask for access.",
          "Sin el motor, las apps nuevas no pueden pedir acceso."),
        E("Unknown applications are blocked until you decide.", "Las apps desconocidas quedan bloqueadas hasta decidir."),
        E("Unknown applications connect. Saved rules still apply.",
          "Las apps desconocidas se conectan. Las reglas guardadas siguen valiendo."),
        E("The GateBouncer engine is not running", "El motor de GateBouncer no está en marcha"),
        E("Saved rules and the block on unknown applications still apply, but nothing can ask you. Restart Windows or "
          "run the installer again.",
          "Las reglas guardadas y el bloqueo de las apps desconocidas siguen valiendo, pero nada puede preguntar. "
          "Reiniciar Windows o volver a correr el instalador."),
        E("Unknown applications can connect", "Las apps desconocidas pueden conectarse"),
        E("Asking is off. Saved Allow and Block rules still apply.",
          "Preguntar está apagado. Las reglas guardadas de Permitir y Bloquear siguen valiendo."),
        E("Only the selected test applications ask before connecting. Rules disappear when the engine stops.",
          "Solo las apps de prueba elegidas preguntan antes de conectarse. Las reglas desaparecen cuando el motor se "
          "detiene."),
        E("GateBouncer is protecting this PC", "GateBouncer protege esta PC"),
        E("Engine running since %1", "Motor en marcha desde %1"),
        E("local network connects without asking", "la red local se conecta sin preguntar"),
        E("local network asks first", "la red local pregunta antes"),
        E("view only", "solo lectura"),
        E("Turn asking on", "Activar las preguntas"),
        E("Firewall settings", "Ajustes del firewall"),
        E("GateBouncer blocks any program that has no rule and asks you in a notice.",
          "GateBouncer bloquea todo programa que no tenga regla y pregunta en un aviso."),
        E("Choose <b>Allow</b> or <b>Block</b> there, or later in <b>Requests</b>.",
          "Elegir <b>Permitir</b> o <b>Bloquear</b> ahí, o más tarde en <b>Pedidos</b>."),
        E("The first attempt of a program fails; <b>Allow</b> lets its next attempt connect.",
          "El primer intento de un programa falla; <b>Permitir</b> deja conectar su próximo intento."),
        E("A program with a rule never asks again. The engine is a Windows service: closing this window keeps the "
          "firewall working. Turn the switch off to let everything without a rule connect; Block rules still apply.",
          "Un programa con regla no vuelve a preguntar. El motor es un servicio de Windows: cerrar esta ventana deja el "
          "firewall funcionando. Apagar el interruptor deja conectar todo lo que no tenga regla; las reglas de bloqueo "
          "siguen valiendo."),
        E("Waiting for you", "Esperando una decisión"),
        E("%1 waiting", "%1 en espera"),
        E("Open Requests", "Abrir Pedidos"),
        E("Nothing is waiting. A new application that tries to connect appears here and in a notice.",
          "No hay nada en espera. Una app nueva que intente conectarse aparece acá y en un aviso."),
        E("Wants %1 · first try %2", "Quiere ir a %1 · primer intento %2"),
        E("Block and Allow here use the choices the notice would preselect: %1this app, any version</span> when it is "
          "signed, %1this app in its repository</span> for an unsigned build inside a Git repository, %1this "
          "file</span> otherwise, and %1only that server</span> for an app that already has server rules. Open the "
          "request to choose another.",
          "Bloquear y Permitir acá usan lo que el aviso preseleccionaría: %1esta app, cualquier versión</span> si está "
          "firmada, %1esta app en su repositorio</span> para un build sin firma dentro de un repositorio Git, %1este "
          "archivo</span> en los demás casos, y %1solo ese servidor</span> para una app que ya tiene reglas por "
          "servidor. Abrir el pedido para elegir otra cosa."),
        E("Rules", "Reglas"),
        E("Open Apps", "Abrir Apps"),
        E("count|allow", "permitidas"),
        E("count|block", "bloqueadas"),
        E("count|temporary", "temporales"),
        E("Apps from %1", "Apps de %1"),
        E("Apps in %1", "Apps en %1"),
        E("%1 in %2", "%1 en %2"),
        E("%1 can connect until restart.", "%1 puede conectarse hasta reiniciar."),
        E("%1 can connect until %2.", "%1 puede conectarse hasta %2."),
        E("%1 can stay blocked until restart.", "%1 sigue con bloqueo hasta reiniciar."),
        E("%1 can stay blocked until %2.", "%1 sigue con bloqueo hasta %2."),
        E("1 of them only for one server.", "1 de ellas solo para un servidor."),
        E("%1 of them only for one server.", "%1 de ellas solo para un servidor."),
        E("Blocked recently", "Bloqueos recientes"),
        E("Nothing blocked since the engine started.", "Nada bloqueado desde que arrancó el motor."),
        E("You allowed · %1", "Permitido · %1"),
        E("You blocked · %1", "Bloqueado · %1"),
        E("Allowed by your rule", "Permitido por una regla"),
        E("Your Block rule", "Regla de bloqueo"),
        E("Request closed", "Pedido cerrado"),

        // ---------- Pedidos
        E("1 attempt since %1", "1 intento desde %1"),
        E("%1 attempts since %2", "%1 intentos desde %2"),
        E("Review", "Revisar"),
        E("This app already has rules for other servers: Allow or Block applies to this server only. Choose Any "
          "destination (whole app) to replace its server rules.",
          "Esta app ya tiene reglas para otros servidores: Permitir o Bloquear vale solo para este servidor. Elegir "
          "Cualquier destino (toda la app) para reemplazar sus reglas por servidor."),
        E("Each application here was blocked and is waiting. Allow lets its next attempt connect.",
          "Cada app de esta lista fue bloqueada y está esperando. Permitir deja conectar su próximo intento."),
        E("Each program here was blocked and is waiting for you.",
          "Cada programa de esta lista fue bloqueado y espera una decisión."),
        E("Choose what the rule covers: <b>this file</b>, <b>any version</b> of a signed app or the app inside its "
          "<b>repository</b>, and for how long and to which server.",
          "Elegir qué cubre la regla: <b>este archivo</b>, <b>cualquier versión</b> de una app firmada o la app dentro "
          "de su <b>repositorio</b>, y por cuánto tiempo y hacia qué servidor."),
        E("Press <b>Allow</b> or <b>Block</b>. Allow lets the next attempt connect.",
          "Presionar <b>Permitir</b> o <b>Bloquear</b>. Permitir deja conectar el próximo intento."),
        E("Closing a notice keeps the request waiting here. Block and Allow on a closed card use what the notice would "
          "preselect.",
          "Cerrar un aviso deja el pedido esperando acá. Bloquear y Permitir en una tarjeta cerrada usan lo que el aviso "
          "preseleccionaría."),
        E("The engine is not running, so no requests can arrive.",
          "El motor no está en marcha, así que no puede llegar ningún pedido."),
        E("Nothing is waiting. A new application that tries to connect appears here and in a notice in the corner of "
          "the screen.",
          "No hay nada en espera. Una app nueva que intente conectarse aparece acá y en un aviso en la esquina de la "
          "pantalla."),

        // ---------- Apps: lista
        E("Every application with a rule. A signed app keeps its rule across updates; a rule in a folder also covers "
          "builds made there later.",
          "Todas las apps con regla. Una app firmada conserva su regla al actualizarse; una regla de carpeta también "
          "cubre los builds que se hagan ahí más adelante."),
        E("Every program with a rule is listed here, with what it covers and where it may connect.",
          "Acá está cada programa con regla, con lo que cubre y adónde puede conectarse."),
        E("A <b>signed</b> program keeps its rule across updates; a <b>folder rule</b> covers every build made inside "
          "that folder.",
          "Un programa <b>firmado</b> conserva su regla al actualizarse; una <b>regla de carpeta</b> cubre cada build "
          "que se haga dentro de esa carpeta."),
        E("Click a row to change or remove its rule. <b>Running, no rule</b> lets you decide before a program asks.",
          "Hacer clic en una fila para cambiar o quitar su regla. <b>En uso, sin regla</b> permite decidir antes de "
          "que un programa pregunte."),
        E("Search apps or publishers", "Buscar apps o editores"),
        E("Trust a folder…", "Confiar en una carpeta…"),
        E("All", "Todas"),
        E("filter|Allow", "Permitidas"),
        E("filter|Block", "Bloqueadas"),
        E("Per server", "Por servidor"),
        E("Temporary", "Temporales"),
        E("Folders", "Carpetas"),
        E("Running, no rule", "En uso, sin regla"),
        E("APPLICATION", "APLICACIÓN"),
        E("FOLDER", "CARPETA"),
        E("RULE FOR THIS FILE", "REGLA PARA ESTE ARCHIVO"),
        E("DESTINATION", "DESTINO"),
        E("RULE", "REGLA"),
        E("WHEN", "CUÁNDO"),
        E("Applications running in your Windows session without a rule. They ask the first time they connect, or "
          "Allow and Block here save a rule for that file now.",
          "Apps abiertas en esta sesión de Windows que no tienen regla. Preguntan la primera vez que se conectan, o "
          "Permitir y Bloquear acá guardan ya una regla para ese archivo."),
        E("1 server", "1 servidor"),
        E("%1 servers", "%1 servidores"),
        E("Anywhere", "Cualquiera"),
        E("Allow · until restart", "Permitir · hasta reiniciar"),
        E("Block · until restart", "Bloquear · hasta reiniciar"),
        E("Allow · until %1", "Permitir · hasta %1"),
        E("Block · until %1", "Bloquear · hasta %1"),
        E("blocked %1", "bloqueo %1"),
        E("added %1", "creada %1"),
        E("A folder rule covers programs in that folder and its subfolders, also ones built or copied there later. A "
          "notice offers it for one app in its repository; Trust a folder… adds any folder by hand, for one program "
          "name or for all of them.",
          "Una regla de carpeta cubre los programas de esa carpeta y sus subcarpetas, también los que se compilen o se "
          "copien ahí más adelante. Un aviso la ofrece para una app en su repositorio; Confiar en una carpeta… agrega "
          "cualquier carpeta a mano, para un nombre de programa o para todos."),
        E("Every running application of this session has a rule or is waiting.",
          "Todas las apps abiertas de esta sesión tienen regla o están esperando."),
        E("No app matches the search.", "Ninguna app coincide con la búsqueda."),
        E("No folder rules yet.", "Todavía no hay reglas de carpeta."),
        E("No rules here yet.", "Todavía no hay reglas acá."),
        E("This file · %1", "Este archivo · %1"),
        E("Any version · %1", "Cualquier versión · %1"),
        E("All apps in %1", "Todas las apps de %1"),
        E("Folder rule · %1", "Regla de carpeta · %1"),
        E("Anywhere in %1", "En cualquier lugar de %1"),
        E("Publisher rule", "Regla de editor"),

        // ---------- Apps: detalle de una app
        E("‹ Apps", "‹ Apps"),
        E("This app has no rules any more.", "Esta app ya no tiene reglas."),
        E("Every program in %1 and its subfolders", "Todos los programas de %1 y sus subcarpetas"),
        E("%1 anywhere in %2 and its subfolders", "%1 en cualquier lugar de %2 y sus subcarpetas"),
        E("Any version signed by %1", "Cualquier versión firmada por %1"),
        E("Any application signed by %1", "Cualquier app firmada por %1"),
        E("%1 · any version signed by %2", "%1 · cualquier versión firmada por %2"),
        E("The <b>Rule</b> card says what this rule covers and when it last blocked an attempt.",
          "La tarjeta <b>Regla</b> dice qué cubre esta regla y cuándo bloqueó un intento por última vez."),
        E("A rule for a file or a folder can change between <b>Allow</b> and <b>Block</b> here; a rule for a signed "
          "app changes on its next notice.",
          "Una regla de un archivo o de una carpeta puede pasar de <b>Permitir</b> a <b>Bloquear</b> acá; la de una app "
          "firmada cambia en su próximo aviso."),
        E("<b>Remove</b> drops the rule: the program asks again the next time it connects, unless a folder rule covers "
          "it.",
          "<b>Quitar</b> borra la regla: el programa vuelve a preguntar la próxima vez que se conecte, salvo que lo "
          "cubra una regla de carpeta."),
        E("Server rules", "Reglas por servidor"),
        E("Remove only this server rule", "Quitar solo la regla de este servidor"),
        E("Any other server asks first, with its own notice. A name is matched through the address the app looked up, "
          "so on a shared network like Cloudflare an allowed address also reaches other sites there.",
          "Cualquier otro servidor pregunta antes, con su propio aviso. Un nombre se reconoce por la dirección que buscó "
          "la app, así que en una red compartida como Cloudflare una dirección permitida también llega a otros sitios "
          "de ahí."),
        E("Decision", "Decisión"),
        E("Applies to", "Se aplica a"),
        E("Any version of %1 signed by this publisher", "Cualquier versión de %1 firmada por este editor"),
        E("%1, also programs built or copied there later. A rule for a file, an app or a publisher comes first.",
          "%1, también los programas que se compilen o se copien ahí más adelante. Una regla de un archivo, una app o "
          "un editor va primero."),
        E("Files seen", "Archivos vistos"),
        E("Created", "Creada"),
        E("Last blocked attempt", "Último intento bloqueado"),
        E("Change to Allow", "Cambiar a Permitir"),
        E("Change to Block", "Cambiar a Bloquear"),
        E("Inside a trusted folder", "Dentro de una carpeta de confianza"),
        E("%1 is a trusted folder. This file rule comes first; if you remove it, the folder rule takes over after one "
          "blocked attempt.",
          "%1 es una carpeta de confianza. Esta regla del archivo va primero; si se quita, decide la regla de la "
          "carpeta después de un intento bloqueado."),
        E("Inside a blocked folder", "Dentro de una carpeta bloqueada"),
        E("A folder rule blocks %1 in %2. This file rule comes first; if you remove it, the folder rule blocks it "
          "without asking.",
          "Una regla de carpeta bloquea %1 en %2. Esta regla del archivo va primero; si se quita, la regla de la carpeta "
          "lo bloquea sin preguntar."),
        E("Cover new builds too", "Cubrir también los builds nuevos"),
        E("This rule covers only this file: a build of %1 in another folder asks again. A rule for %1 anywhere in %2 "
          "covers every build there.",
          "Esta regla cubre solo este archivo: un build de %1 en otra carpeta vuelve a preguntar. Una regla para %1 en "
          "cualquier lugar de %2 cubre todos los builds de ahí."),
        E("Cover all builds…", "Cubrir todos los builds…"),
        E("Remove all rules for %1", "Quitar todas las reglas de %1"),
        E("Remove this rule", "Quitar esta regla"),
        E("The trusted folder decides for %1 after one blocked attempt.",
          "La carpeta de confianza decide por %1 después de un intento bloqueado."),
        E("The folder rule blocks %1 without asking.", "La regla de la carpeta bloquea %1 sin preguntar."),
        E("%1 asks again the next time it connects.", "%1 vuelve a preguntar la próxima vez que se conecte."),
        E("Programs in %1 ask again the next time they connect, unless another rule covers them.",
          "Los programas de %1 vuelven a preguntar la próxima vez que se conecten, salvo que los cubra otra regla."),
        E("%1 asks again the next time it connects. To change a rule like this one, decide on its next notice.",
          "%1 vuelve a preguntar la próxima vez que se conecte. Para cambiar una regla como esta, decidir en su próximo "
          "aviso."),
        E("Remove rule", "Quitar regla"),
        E("Remove rules", "Quitar reglas"),

        // ---------- Actividad
        E("Blocked", "Bloqueos"),
        E("Decisions", "Decisiones"),
        E("Since the engine started at %1. Allowed connections are not recorded.",
          "Desde que arrancó el motor (%1). Las conexiones permitidas no se registran."),
        E("Allowed connections are not recorded.", "Las conexiones permitidas no se registran."),
        E("<b>Blocked</b> lists every attempt the engine stopped and how each request ended.",
          "<b>Bloqueos</b> lista cada intento que frenó el motor y cómo terminó cada pedido."),
        E("<b>Decisions</b> shows what you chose and when one of your rules let a program through.",
          "<b>Decisiones</b> muestra lo que se eligió y cuándo una regla dejó pasar a un programa."),
        E("Repeated attempts of one program are grouped in one row.",
          "Los intentos repetidos de un mismo programa se juntan en una fila."),
        E("The list keeps the latest 2,000 events and starts again when the engine restarts.",
          "La lista guarda los últimos 2000 eventos y vuelve a empezar cuando el motor se reinicia."),
        E("TIME", "HORA"),
        E("REASON", "MOTIVO"),
        E("DECISION", "DECISIÓN"),
        E("%1 times", "%1 veces"),
        E("%1 +%2 more", "%1 +%2 más"),
        E("No decisions since the engine started.", "Ninguna decisión desde que arrancó el motor."),

        // ---------- Ajustes: firewall
        E("Firewall mode, updates, language, zoom, AI explanations and import.",
          "Modo del firewall, actualizaciones, idioma, zoom, explicaciones con IA e importación."),
        E("<b>App</b> looks for new versions at startup and every few hours, and sets the language and the zoom of this "
          "window.",
          "<b>App</b> busca versiones nuevas al iniciar y cada pocas horas, y elige el idioma y el zoom de esta ventana."),
        E("<b>Ask before unknown applications connect</b> is the switch of Protection: off, everything without a rule "
          "connects.",
          "<b>Preguntar antes de que se conecten apps desconocidas</b> es el interruptor de Protección: apagado, se "
          "conecta todo lo que no tenga regla."),
        E("<b>AI explanations</b> need your own key and your consent; they only explain, they never allow or block.",
          "Las <b>explicaciones con IA</b> necesitan una key propia y el consentimiento; solo explican, nunca permiten "
          "ni bloquean."),
        E("<b>Import from NetLimiter</b> turns its rules for single applications into GateBouncer rules.",
          "<b>Importar de NetLimiter</b> convierte sus reglas de una sola app en reglas de GateBouncer."),
        E("Closing the window keeps the firewall running: the engine is a Windows service. Quit in the tray menu closes "
          "only this window.",
          "Cerrar la ventana deja el firewall funcionando: el motor es un servicio de Windows. Salir, en el menú de la "
          "bandeja, cierra solo esta ventana."),
        E("Off lets everything without a rule connect. Block rules still apply.",
          "Apagado, se conecta todo lo que no tenga regla. Las reglas de bloqueo siguen valiendo."),
        E("Allow the local network without asking", "Permitir la red local sin preguntar"),
        E("Other computers, printers and storage at home or the office, and devices on Tailscale. A Block rule for an "
          "application still applies there.",
          "Otras computadoras, impresoras y discos de la casa o la oficina, y los equipos de Tailscale. Una regla de "
          "bloqueo de una app sigue valiendo ahí."),
        E("Windows services, DNS and connections inside this PC always connect. To turn GateBouncer off completely, "
          "run %1 as administrator.",
          "Los servicios de Windows, el DNS y las conexiones dentro de esta PC siempre se conectan. Para apagar "
          "GateBouncer del todo, correr %1 como administrador."),
        E("The engine is not running: these options apply when it starts again.",
          "El motor no está en marcha: estas opciones se aplican cuando vuelva a arrancar."),

        // ---------- Ajustes: explicaciones con IA
        E("AI explanations", "Explicaciones con IA"),
        E("Ready", "Listas"),
        E("Key saved", "Key guardada"),
        E("Off", "Apagadas"),
        E("When an application is blocked, an AI model can say what it is and why it connects. The answer only helps "
          "you decide: it never allows or blocks anything, and it can be wrong.",
          "Cuando una app queda bloqueada, un modelo de IA puede decir qué es y por qué se conecta. La respuesta solo "
          "ayuda a decidir: nunca permite ni bloquea nada, y puede equivocarse."),
        E("Paste a new key", "Pegar una key nueva"),
        E("Paste your key (%1…)", "Pegar la key (%1…)"),
        E("Save key", "Guardar key"),
        E("%1 key", "Key de %1"),
        E("Saved for this Windows account, encrypted.", "Guardada para esta cuenta de Windows, cifrada."),
        E("No key saved: explanations are off.", "Sin key guardada: las explicaciones están apagadas."),
        E("Send app details to %1 when an explanation is requested",
          "Mandar los datos de la app a %1 cuando se pide una explicación"),
        E("The file name, its folder without your account name, signature and version, the public server it wanted and "
          "the program that started it. Never the file, its command line or your local network. Uses your %1 account "
          "and its terms; up to 100 a day.",
          "El nombre del archivo, su carpeta sin el nombre de la cuenta, la firma y la versión, el servidor público al "
          "que quería ir y el programa que lo lanzó. Nunca el archivo, su línea de comandos ni la red local. Usa la "
          "cuenta propia de %1 y sus términos; hasta 100 por día."),
        E("Explain automatically when a notice appears", "Explicar automáticamente al aparecer un aviso"),
        E("Off shows an Ask AI button on the notice instead.",
          "Apagado, el aviso muestra en cambio un botón Preguntar a la IA."),
        E("Test with Notepad", "Probar con el Bloc de notas"),
        E("Model and language", "Modelo e idioma"),
        E("%1 key saved for this Windows account.", "Key de %1 guardada para esta cuenta de Windows."),
        E("%1 key removed.", "Key de %1 quitada."),
        E("Asking %1 about notepad.exe…", "Preguntando a %1 por notepad.exe…"),
        E("Working · %1 s · %2", "Funciona · %1 s · %2"),
        E("Not working: %1", "No funciona: %1"),

        // ---------- Ajustes: importar y colofón
        E("Import from NetLimiter", "Importar de NetLimiter"),
        E("Turns NetLimiter firewall rules for single applications into GateBouncer rules.",
          "Convierte las reglas de firewall de NetLimiter para una sola app en reglas de GateBouncer."),
        E("Choose file…", "Elegir archivo…"),
        E("Developed by Lega Pugliese ·", "Desarrollado por Lega Pugliese ·"),
        E("Opens at sign-in, minimized to the tray. Closing the window hides it; the firewall keeps working either way.",
          "Se abre al iniciar sesión, minimizada en la bandeja. Cerrar la ventana la oculta; el firewall sigue "
          "funcionando igual."),

        // ---------- Ajustes: App
        E("App", "App"),
        E("Could not restart the window. The change applies the next time it opens.",
          "No se pudo reiniciar la ventana. El cambio se aplica la próxima vez que se abra."),
        E("Check for updates at startup", "Buscar actualizaciones al iniciar"),
        E("Installed version: v%1", "Versión instalada: v%1"),
        E("Check now", "Buscar ahora"),
        E("Updates are off in this copy.", "Esta copia no se actualiza."),
        E("This copy is not the installed one: it does not update itself.",
          "Esta copia no es la instalada: no se actualiza sola."),
        E("Language", "Idioma"),
        E("Zoom", "Zoom"),
        E("Colors", "Colores"),
        E("Violet", "Violeta"),
        E("Magenta", "Magenta"),
        E("High contrast", "Alto contraste"),
        E("Graphite | amber", "Grafito | ámbar"),
        E("Mist", "Niebla"),
        E("Warm teal", "Cálido turquesa"),
        E("%1%", "%1 %"),
        E("%1 is the default. Changing the zoom or the language restarts the window.",
          "%1 es el predeterminado. Cambiar el zoom o el idioma reinicia la ventana."),
        E("Only %1 fits on this screen.", "En esta pantalla solo entra el %1."),
        E("Up to %1 fits on this screen.", "En esta pantalla entra hasta el %1."),

        // ---------- Importar de NetLimiter
        E("‹ Settings", "‹ Ajustes"),
        E("NetLimiter keeps its rules in nl_settings.xml.", "NetLimiter guarda sus reglas en nl_settings.xml."),
        E("%1 · %2 NetLimiter rules · %3 can be imported", "%1 · %2 reglas de NetLimiter · se pueden importar %3"),
        E("Choose the <b>nl_settings.xml</b> file of NetLimiter.", "Elegir el archivo <b>nl_settings.xml</b> de NetLimiter."),
        E("Rules for one application, outgoing, active, Allow or Deny, can be imported; the rest are listed with the "
          "reason.",
          "Se pueden importar las reglas de una sola app, de salida, activas, Allow o Deny; el resto se lista con el "
          "motivo."),
        E("Press <b>Import</b> to add them as GateBouncer rules for those files.",
          "Presionar <b>Importar</b> para agregarlas como reglas de GateBouncer para esos archivos."),
        E("No file chosen.", "No se eligió ningún archivo."),
        E("Choose NetLimiter settings file", "Elegir el archivo de ajustes de NetLimiter"),
        E("NetLimiter settings (nl_settings.xml *.xml);;All files (*)",
          "Ajustes de NetLimiter (nl_settings.xml *.xml);;Todos los archivos (*)"),
        E("The file could not be opened.", "No se pudo abrir el archivo."),
        E("NETLIMITER RULE", "REGLA DE NETLIMITER"),
        E("IN GATEBOUNCER", "EN GATEBOUNCER"),
        E("Already has a rule (Allow)", "Ya tiene una regla (Permitir)"),
        E("Already has a rule (Block)", "Ya tiene una regla (Bloquear)"),
        E("Will be allowed", "Se va a permitir"),
        E("Will be blocked", "Se va a bloquear"),
        E("Not imported: %1", "No se importa: %1"),
        E("Rules limited to addresses, ports, zones or schedules, Ask rules and incoming-only rules are listed and not "
          "imported. Nothing changes until you import.",
          "Las reglas limitadas a direcciones, puertos, zonas u horarios, las reglas Ask y las que son solo de entrada "
          "se listan y no se importan. Nada cambia hasta importar."),
        E("Import 1 rule", "Importar 1 regla"),
        E("Import %1 rules", "Importar %1 reglas"),
        E("Importing 1 rule from NetLimiter…", "Importando 1 regla de NetLimiter…"),
        E("Importing %1 rules from NetLimiter…", "Importando %1 reglas de NetLimiter…"),
        // Errores al leer el archivo (src/engine/NetLimiterRules.cpp).
        E("The file is nested too deeply to be a NetLimiter settings file.",
          "El archivo tiene demasiados niveles para ser un archivo de ajustes de NetLimiter."),
        E("This is not a valid XML file (line %1): %2", "No es un archivo XML válido (línea %1): %2"),
        E("The file is too large to be a NetLimiter settings file.",
          "El archivo es demasiado grande para ser un archivo de ajustes de NetLimiter."),
        E("No NetLimiter filters and rules were found in this file. Choose nl_settings.xml from NetLimiter.",
          "No se encontraron filtros ni reglas de NetLimiter en este archivo. Elegir el nl_settings.xml de NetLimiter."),
        // Motivos por los que una regla no se importa: sólo se muestran después de «No se importa:», en minúscula.
        E("Combines other NetLimiter filters", "combina otros filtros de NetLimiter"),
        E("Filter without conditions", "filtro sin condiciones"),
        E("Also limited by destination, port or other conditions", "también limitada por destino, puerto u otras condiciones"),
        E("Not an application filter", "no es un filtro de app"),
        E("Inverted application filter", "filtro de app invertido"),
        E("Application not identified by path", "app sin identificar por ruta"),
        E("Both Allow and Deny rules exist for this application", "esta app tiene reglas Allow y Deny a la vez"),
        E("Its filter is missing from the file", "falta su filtro en el archivo"),
        E("Disabled in NetLimiter", "desactivada en NetLimiter"),
        E("Incoming connections only", "solo conexiones de entrada"),
        E("Ask rule: GateBouncer already asks", "regla Ask: GateBouncer ya pregunta"),
        E("Unknown action", "acción desconocida"),
        E("File not found on this PC", "el archivo no está en esta PC"),

        // ---------- Bandeja
        E("tray|Open", "Abrir"),
        E("tray|Quit", "Salir"),
        E("Pending (%1)", "Pedidos (%1)"),
        E("Simulation: no traffic filtering", "Simulación: no se filtra el tráfico"),
        E("Asking before new apps connect", "Pregunta antes de que se conecten apps nuevas"),
        E("Not asking: new apps connect", "Sin preguntar: las apps nuevas se conectan"),
        E("Engine degraded", "Motor con fallas"),
        E("Engine unavailable", "Motor no disponible"),
        E("LGA GateBouncer\n%1\n1 pending request", "LGA GateBouncer\n%1\n1 pedido pendiente"),
        E("LGA GateBouncer\n%1\n%2 pending requests", "LGA GateBouncer\n%1\n%2 pedidos pendientes"),
    };
    return table;
}

} // namespace Gate::I18n
