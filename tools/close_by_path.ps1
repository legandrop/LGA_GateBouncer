# close_by_path.ps1 -- rev 4 (2026-09-18)
#
# La copia CANONICA vive en LGA_Base_QT_C_Py\tools\close_by_path.ps1. Cada app lleva en su propio
# tools\ una copia IDENTICA, esta cabecera incluida (solo pueden cambiar los fines de linea), y no
# la modifica: los arreglos se hacen en la canonica y se vuelven a copiar. Asi esta cabecera es
# cierta en cualquier repo, y comparar una copia con la canonica es un diff sin excepciones.
#
# Cierra procesos de UN ejecutable (-ExeName) decidiendo por su ruta REAL
# (Win32_Process.ExecutablePath). Tiene dos modos:
#
#   POR RUTA (rev 1-2, sin cambios): cierra los -ExeName que viven adentro de una carpeta (-Prefix)
#   o que son exactamente un archivo (-ExactPath). Es el modo de `compilar.bat --no-run`, de
#   `limpiar`, de `deploy` y de los backends: cierra SOLO la copia que se va a pisar o borrar.
#
#   TODAS LAS INSTANCIAS (-AllInstances, rev 3; guardas de sistema en rev 4): las apps LGA son de instancia unica, asi que
#   `compilar.bat` normal (el que compila y lanza) y el instalador cierran TODAS las copias de la
#   app -la instalada, la de build, las de otros checkouts- mas sus AUXILIARES (-Helpers: backend
#   Python, redis, engines). El exe principal se elige por nombre; los auxiliares NUNCA: se cierran
#   solo los que viven adentro de la carpeta de una instancia cerrada o de un -HelperPrefix. Asi,
#   compilar FileManagerS3 cierra todos los FileManagerS3.exe con sus redis-server.exe, pero no el
#   redis-server.exe de PipeSync, que vive en otra carpeta.
#
# Por que existe: los scripts de build hacian `taskkill /F /IM <App>.exe`, que cierra TODAS las
# copias de la app sin cerrar sus auxiliares, y los auxiliares se cerraban por nombre o por linea
# de comandos, que no distinguen una app de otra ni una instalacion de un build. Referencias de las
# que sale: tools/kill_scenebuilder.ps1 de LGA_SceneBuilder (filtro por ExecutablePath) y el
# compilar.bat de LGA_FrameRev (ruta exacta del exe).
#
# USO (siempre con -File, desde un .bat o desde el [Code] de Inno):
#   Por ruta:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\close_by_path.ps1 ^
#       -ExeName App.exe -ExactPath "%APP_ROOT%build\App.exe"
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\close_by_path.ps1 ^
#       -ExeName App_py.exe -Prefix "%APP_ROOT%python_runtime" -Tree -TreeAllow "%APP_ROOT%thirdparty"
#   ... -Prefix "%APP_ROOT%build,%APP_ROOT%build-release" -DryRun
#   Todas las instancias (el "." final evita que la \ de %APP_ROOT% escape la comilla de cierre):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\close_by_path.ps1 ^
#       -ExeName App.exe -AllInstances -Helpers App_py.exe,redis-server.exe -HelperPrefix "%APP_ROOT%." -Tree
#
# Parametros:
#   -ExeName    OBLIGATORIO. Nombre de imagen, solo el nombre (`App.exe`), sin ruta ni comodines.
#               Es obligatorio para que un prefijo amplio no alcance a OTRO ejecutable que vive
#               abajo: el instalador del auto-update que corre desde {app}\updates, o el
#               python.exe de un runtime que comparten los hooks de varios repos.
#   -Prefix     Una o mas carpetas ABSOLUTAS separadas por coma (con o sin espacios alrededor).
#               Matchea todo exe que viva adentro, a cualquier profundidad.
#   -ExactPath  Una o mas rutas ABSOLUTAS de exe, separadas por coma. Matchea solo ese archivo.
#               Es el modo de `compilar.bat --no-run`: el linker necesita libre ESE archivo y
#               ningun otro. Su nombre de archivo tiene que ser -ExeName.
#               Sin -AllInstances hace falta -Prefix, -ExactPath o los dos.
#   -Tree       Cierra tambien los DESCENDIENTES de cada proceso que se cierra (hijos, nietos, y
#               tambien los lanzados desacoplados, con DETACHED_PROCESS: se encuentran por el
#               PID padre, no por la consola). Pero SOLO los que viven adentro de una carpeta del
#               filtro (-Prefix, -ExactPath; con -AllInstances, la carpeta de la instancia y los
#               -HelperPrefix) o de un -TreeAllow. El resto se lista y se deja vivo, y tampoco se
#               baja por su rama: lo que cuelga de un proceso que se deja vivo es de ese proceso.
#   -TreeAllow  Carpetas ABSOLUTAS de helpers conocidos que el backend lanza y que viven fuera
#               del filtro (ffmpeg en thirdparty\, redis, el python del runtime). Requiere -Tree.
#   -DryRun     Lista lo que cerraria y no cierra nada; con -Tree lista TODOS los descendientes
#               con su ruta y que haria con cada uno. Usarlo ANTES de correr por primera vez un
#               .bat real que se modifico.
#
#   Solo con -AllInstances (y -AllInstances no admite -Prefix ni -ExactPath):
#   -AllInstances  Cierra TODOS los -ExeName, vivan donde vivan. Se rechaza con nombres genericos
#               (python.exe, redis-server.exe, powershell.exe...): el nombre tiene que ser el de
#               la app. Cada instancia cerrada aporta su CARPETA para buscar auxiliares:
#                 - si es un arbol de build (hay un CMakeCache.txt en la carpeta del exe o hasta dos
#                   niveles arriba, y su CMAKE_HOME_DIRECTORY es una carpeta con CMakeLists.txt que
#                   contiene a ese arbol), la carpeta es la RAIZ DEL REPO: asi entran python_runtime\
#                   y thirdparty\ de ese checkout. Se decide por estructura, nunca por el nombre;
#                 - si no, la carpeta del exe (la instalacion, {app}; deploy\).
#               Esa carpeta pasa por las mismas guardas que un -HelperPrefix; si no las pasa, la
#               instancia se cierra igual pero su carpeta no se usa (queda en el log).
#               La raiz del repo sale de la ESTRUCTURA, no de la app: en un monorepo con dos apps
#               bajo el mismo CMakeLists.txt raiz, las dos comparten esa carpeta, y compilar una
#               cierra los -Helpers que la otra tenga corriendo desde ese repo. Hoy ninguna app LGA
#               es asi; si aparece una, sus auxiliares llevan nombre propio (App_py.exe).
#   -Helpers    Nombres de imagen de los auxiliares, separados por coma (`App_py.exe,redis-server.exe`).
#               Se cierra cada proceso con ese nombre que viva adentro de la carpeta de una
#               instancia cerrada o de un -HelperPrefix, este o no colgado de la app (un redis
#               desacoplado, o huerfano de una instancia que se cayo). Nunca por nombre solo.
#               Se rechazan los procesos del sistema (svchost, csrss, lsass, winlogon, dwm,
#               explorer, conhost, services, smss, wininit y parientes): ninguna app LGA los lanza.
#   -HelperPrefix  Carpetas ABSOLUTAS extra donde tambien se buscan auxiliares, aunque ninguna
#               instancia este corriendo desde ahi: el repo propio en compilar.bat, {app} en el
#               instalador. Tambien cuentan como carpeta para -Tree.
#   -ExceptPrefix  Carpetas ABSOLUTAS que NUNCA se tocan, ni la app ni auxiliares ni descendientes:
#               otra edicion de la app que comparte el nombre de imagen (PipeSync_Client).
#
# Por que -Tree NO cierra todo el arbol (rev 1 usaba `taskkill /T`, que si lo hace): un backend
# puede abrir OTRA app LGA como proceso aparte (abrir un archivo en el Player, lanzar el
# FileManager). Ese proceso es hijo del backend, pero es trabajo del usuario: `taskkill /T` lo
# cerraba, desacoplado o no. Dejar vivo un helper que no se nombro es la direccion segura: si
# retiene un archivo, el linker o Inno avisan "archivo en uso", y la linea del log dice cual es
# y donde vive para agregarlo a -TreeAllow o a -Helpers.
#
# Guardas (un parametro invalido NO cierra nada; se avisa y se sale con 2):
#   - Rutas solo absolutas (`C:\...` o `\\servidor\recurso\...`). Se rechazan vacias, relativas
#     (`build`: es lo que queda de "%APP_ROOT%build" con APP_ROOT vacio), `C:carpeta`, comodines,
#     comillas sueltas, la raiz de una unidad y cualquier ruta con menos de DOS componentes debajo
#     de la unidad o del recurso compartido (`C:\Portable` se rechaza; `C:\Portable\App` no).
#   - -Prefix, -TreeAllow y -HelperPrefix rechazan ademas las RAICES COMUNES de las instalaciones
#     LGA (`<unidad>:\Portable\LGA` en todas las unidades de A a Z, `C:\Program Files\LGA`, `C:\Program Files (x86)\LGA`,
#     `%LOCALAPPDATA%\LGA`, `%APPDATA%\LGA`) y cualquier carpeta que las contenga (el perfil del
#     usuario, `AppData`): con una variable mal armada, un prefijo asi alcanzaria a la instalada.
#     La carpeta de UNA app adentro (`C:\Portable\LGA\VideoDownloader`, el {app} de Inno) si vale.
#   - -HelperPrefix y la carpeta de cada instancia rechazan tambien las carpetas AMPLIAS de Windows
#     y del usuario, iguales o contenedoras: el perfil, Desktop, Downloads, Documents, %TEMP%,
#     Windows, Program Files, ProgramData, AppData, C:\Users. Una app corrida desde Downloads se
#     cierra, pero Downloads no se barre buscando auxiliares.
#   - -HelperPrefix y la carpeta de cada instancia rechazan tambien cualquier carpeta DENTRO de
#     %windir% (`C:\Windows\System32`, `C:\Windows\Temp\x`): ahi viven los procesos del sistema.
#     Una instancia corrida desde ahi se cierra, pero esa carpeta no se barre.
#   - La comparacion de carpetas agrega el separador final: `...\PipeSync` NO matchea
#     `...\PipeSync_Client\...`, y `...\build` NO matchea `...\build-dump\...`.
#   - Un proceso sin ExecutablePath legible (otra sesion, sin privilegios) se deja vivo. Si la
#     consulta de procesos falla entera, no se cierra nada. Las dos son la direccion segura: lo
#     peor que pasa es que el linker o el instalador avisen que el archivo esta en uso.
#
# Salida: 0 si corrio (haya cerrado cero, uno o varios procesos, y aunque alguno no se haya podido
# cerrar: cada caso queda escrito con su PID y su ruta); 2 si rechazo los parametros. Cerrar cero
# procesos no es un error.
#
# Las listas son [string[]] y ademas se parten por coma a mano: invocado con -File, powershell.exe
# entrega "a,b" como UN solo string (bug medido en kill_scenebuilder.ps1). Tampoco se usa
# Mandatory: con -File y sin -NonInteractive, un parametro obligatorio que falta hace que
# PowerShell se quede esperando que alguien lo tipee, y el .bat queda colgado.

param(
    [string]   $ExeName = '',
    [string[]] $Prefix = @(),
    [string[]] $ExactPath = @(),
    [switch]   $Tree,
    [string[]] $TreeAllow = @(),
    [switch]   $DryRun,
    [switch]   $AllInstances,
    [string[]] $Helpers = @(),
    [string[]] $HelperPrefix = @(),
    [string[]] $ExceptPrefix = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$tag = 'close_by_path'

function Write-Line([string] $text) {
    Write-Host "${tag}: $text"
}

function Reject([string] $why) {
    Write-Line "RECHAZADO, no se cierra nada: $why"
    exit 2
}

# Parte una lista que puede venir como array, como "a,b" o como las dos cosas.
function Split-List([string[]] $items) {
    $out = @()
    foreach ($item in $items) {
        if ($null -eq $item) { continue }
        foreach ($part in ($item -split ',')) {
            $trimmed = $part.Trim()
            if ($trimmed -ne '') { $out += $trimmed }
        }
    }
    return ,$out
}

# Devuelve la ruta absoluta normalizada, sin separador final, o $null con el motivo en $script:why.
function Resolve-AbsolutePath([string] $raw) {
    $script:why = ''
    $p = $raw.Trim().Replace('/', '\')
    if ($p -eq '') { $script:why = 'ruta vacia'; return $null }
    if ($p -match '["*?<>|]') { $script:why = "caracteres invalidos en '$raw' (comillas o comodines)"; return $null }
    if ($p.StartsWith('\\?\') -or $p.StartsWith('\\.\')) { $script:why = "ruta de dispositivo no admitida: '$raw'"; return $null }

    $isDrive = $p -match '^[A-Za-z]:\\'
    $isUnc = $p -match '^\\\\[^\\]+\\[^\\]+'
    if (-not ($isDrive -or $isUnc)) { $script:why = "no es una ruta absoluta: '$raw'"; return $null }

    try {
        $full = [System.IO.Path]::GetFullPath($p)
    } catch {
        $script:why = "ruta invalida '$raw' ($($_.Exception.Message))"
        return $null
    }
    $full = $full.TrimEnd('\')

    # Componentes debajo de la unidad o del recurso compartido.
    $segments = @($full.Split('\') | Where-Object { $_ -ne '' })
    if ($isDrive) {
        $below = $segments.Count - 1          # C: + componentes
    } else {
        $below = $segments.Count - 2          # servidor + recurso + componentes
    }
    if ($below -lt 2) {
        $script:why = "ruta demasiado corta ('$full'): hacen falta al menos dos carpetas debajo de la unidad o del recurso"
        return $null
    }
    return $full
}

function Get-NormFolders([string[]] $raws) {
    $out = @()
    foreach ($r in $raws) {
        if (-not $r) { continue }
        try { $out += [System.IO.Path]::GetFullPath($r).TrimEnd('\') } catch { }
    }
    return ,$out
}

# Raices comunes de las instalaciones LGA. Un -Prefix o -TreeAllow que sea una de ellas, o que
# contenga a alguna, alcanzaria a las apps instaladas.
function Get-ProtectedRoots {
    # Todas las unidades, sin tocar el disco: una instalacion en D:\Portable\LGA es tan real como
    # una en C:.
    $roots = @()
    foreach ($letter in [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ') { $roots += "${letter}:\Portable\LGA" }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:LOCALAPPDATA, $env:APPDATA)) {
        if ($base) { $roots += (Join-Path $base 'LGA') }
    }
    return (Get-NormFolders $roots)
}

# Carpetas amplias de Windows y del usuario. Una carpeta de auxiliares no puede ser ninguna de
# ellas ni contenerlas: una app corrida desde Downloads no habilita a barrer Downloads.
function Get-BroadFolders {
    $list = @()
    foreach ($v in @($env:USERPROFILE, $env:PUBLIC, $env:TEMP, $env:TMP, $env:windir, $env:SystemRoot,
                     $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:ProgramData,
                     $env:LOCALAPPDATA, $env:APPDATA)) {
        if ($v) { $list += $v }
    }
    if ($env:USERPROFILE) {
        foreach ($sub in @('Desktop', 'Downloads', 'Documents', 'OneDrive')) { $list += (Join-Path $env:USERPROFILE $sub) }
    }
    if ($env:SystemDrive) { $list += ($env:SystemDrive + '\Users') }
    return (Get-NormFolders $list)
}

$protectedRoots = Get-ProtectedRoots
$broadFolders = Get-BroadFolders
# Carpetas de Windows: una carpeta de auxiliares tampoco puede estar ADENTRO (System32, Temp).
$systemFolders = Get-NormFolders @($env:windir, $env:SystemRoot)

# Devuelve la carpeta de la lista que $full es o contiene, o $null.
function Find-Covered([string] $full, [string[]] $roots) {
    foreach ($root in $roots) {
        if ($root.Equals($full, [System.StringComparison]::OrdinalIgnoreCase)) { return $root }
        if ($root.StartsWith($full + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $root }
    }
    return $null
}

function Test-ProtectedFolder([string] $full) {
    return (Find-Covered $full $protectedRoots)
}

# Guardas de una carpeta de auxiliares (-HelperPrefix o carpeta de una instancia). Devuelve el
# motivo del rechazo, o '' si pasa.
function Test-HelperFolder([string] $full) {
    $hit = Test-ProtectedFolder $full
    if ($null -ne $hit) { return "'$full' es (o contiene) la raiz comun de las instalaciones LGA '$hit'" }
    $hit = Find-Covered $full $broadFolders
    if ($null -ne $hit) { return "'$full' es (o contiene) la carpeta amplia '$hit'" }
    foreach ($sys in $systemFolders) {
        if ($full.StartsWith($sys + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            return "'$full' esta dentro de la carpeta de Windows '$sys'"
        }
    }
    return ''
}

function Resolve-FolderList([string[]] $raws, [string] $paramName, [bool] $helperGuards = $false) {
    $out = @()
    foreach ($raw in $raws) {
        $full = Resolve-AbsolutePath $raw
        if ($null -eq $full) { Reject "${paramName}: $script:why" }
        $hit = Test-ProtectedFolder $full
        if ($null -ne $hit) {
            Reject "${paramName}: '$full' es (o contiene) la raiz comun de las instalaciones LGA '$hit'; hay que pasar la carpeta de UNA app"
        }
        if ($helperGuards) {
            $why = Test-HelperFolder $full
            if ($why -ne '') { Reject "${paramName}: $why; hay que pasar la carpeta de UNA app" }
        }
        $out += ($full + '\')
    }
    return ,$out
}

# Nombres de imagen genericos: con -AllInstances cerrarian procesos de cualquier programa.
$genericNames = @(
    'python.exe', 'pythonw.exe', 'py.exe', 'pyw.exe', 'redis-server.exe', 'redis-cli.exe',
    'ffmpeg.exe', 'ffprobe.exe', 'ffplay.exe', 'node.exe', 'deno.exe', 'yt-dlp.exe', 'java.exe',
    'javaw.exe', 'git.exe', 'bash.exe', 'sh.exe', 'cmd.exe', 'conhost.exe', 'powershell.exe',
    'pwsh.exe', 'explorer.exe', 'svchost.exe', 'rundll32.exe', 'dllhost.exe', 'msiexec.exe',
    'wscript.exe', 'cscript.exe', 'mshta.exe', 'setup.exe', 'unins000.exe'
)

# Procesos del sistema: nunca son auxiliares de una app LGA, ni siquiera filtrados por carpeta.
$systemNames = @(
    'svchost.exe', 'csrss.exe', 'lsass.exe', 'lsaiso.exe', 'winlogon.exe', 'dwm.exe', 'explorer.exe',
    'conhost.exe', 'services.exe', 'smss.exe', 'wininit.exe', 'fontdrvhost.exe', 'sihost.exe',
    'taskhostw.exe', 'spoolsv.exe', 'ctfmon.exe', 'runtimebroker.exe', 'dllhost.exe', 'rundll32.exe',
    'wmiprvse.exe', 'audiodg.exe', 'searchindexer.exe', 'msmpeng.exe', 'userinit.exe', 'logonui.exe',
    'system', 'registry', 'memory compression', 'secure system'
)

function Test-ImageName([string] $name) {
    if ($name -match '[\\/:"*?<>|'']') { return $false }
    return $name.EndsWith('.exe', [System.StringComparison]::OrdinalIgnoreCase)
}

# --- Validacion de parametros: nada se consulta ni se cierra hasta pasar todo esto ---

$ExeName = $ExeName.Trim()
if ($ExeName -eq '') { Reject 'falta -ExeName (obligatorio)' }
if ($ExeName -match '[\\/:"*?<>|'']') { Reject "-ExeName tiene que ser solo un nombre de archivo, sin ruta ni comodines: '$ExeName'" }
if (-not $ExeName.EndsWith('.exe', [System.StringComparison]::OrdinalIgnoreCase)) { Reject "-ExeName tiene que terminar en .exe: '$ExeName'" }

$prefixRaw = Split-List $Prefix
$exactRaw = Split-List $ExactPath
$allowRaw = Split-List $TreeAllow
$helperRaw = Split-List $Helpers
$helperPrefixRaw = Split-List $HelperPrefix
$exceptRaw = Split-List $ExceptPrefix
if (($Prefix.Count -gt 0 -and $prefixRaw.Count -eq 0) -or
    ($ExactPath.Count -gt 0 -and $exactRaw.Count -eq 0) -or
    ($TreeAllow.Count -gt 0 -and $allowRaw.Count -eq 0)) {
    Reject 'se paso -Prefix, -ExactPath o -TreeAllow vacio (una variable de entorno sin definir?)'
}
if (($Helpers.Count -gt 0 -and $helperRaw.Count -eq 0) -or
    ($HelperPrefix.Count -gt 0 -and $helperPrefixRaw.Count -eq 0) -or
    ($ExceptPrefix.Count -gt 0 -and $exceptRaw.Count -eq 0)) {
    Reject 'se paso -Helpers, -HelperPrefix o -ExceptPrefix vacio (una variable de entorno sin definir?)'
}
if ($AllInstances) {
    if ($prefixRaw.Count -gt 0 -or $exactRaw.Count -gt 0) {
        Reject '-AllInstances no admite -Prefix ni -ExactPath (las carpetas extra de auxiliares van en -HelperPrefix)'
    }
    if (($genericNames -contains $ExeName.ToLowerInvariant()) -or ($systemNames -contains $ExeName.ToLowerInvariant())) {
        Reject "-AllInstances con un nombre generico ('$ExeName') cerraria procesos de cualquier programa; -ExeName tiene que ser el de la app"
    }
} else {
    if ($helperRaw.Count -gt 0 -or $helperPrefixRaw.Count -gt 0 -or $exceptRaw.Count -gt 0) {
        Reject '-Helpers, -HelperPrefix y -ExceptPrefix solo existen con -AllInstances'
    }
    if ($prefixRaw.Count -eq 0 -and $exactRaw.Count -eq 0) { Reject 'hace falta -Prefix o -ExactPath' }
}
if ($allowRaw.Count -gt 0 -and -not $Tree) { Reject '-TreeAllow solo tiene sentido con -Tree' }

$helperNames = @()
foreach ($h in $helperRaw) {
    if (-not (Test-ImageName $h)) { Reject "-Helpers: '$h' tiene que ser solo un nombre de archivo .exe, sin ruta ni comodines" }
    if ($systemNames -contains $h.ToLowerInvariant()) { Reject "-Helpers: '$h' es un proceso del sistema, no un auxiliar de la app" }
    if ($h.Equals($ExeName, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
    if (-not ($helperNames -contains $h)) { $helperNames += $h }
}

$prefixes = Resolve-FolderList $prefixRaw '-Prefix'
$allows = Resolve-FolderList $allowRaw '-TreeAllow'
$helperPrefixes = Resolve-FolderList $helperPrefixRaw '-HelperPrefix' $true

# -ExceptPrefix solo resta: basta con que sea una ruta absoluta valida (un error de variable se
# rechaza igual, para que no pase desapercibido).
$excepts = @()
foreach ($raw in $exceptRaw) {
    $full = Resolve-AbsolutePath $raw
    if ($null -eq $full) { Reject "-ExceptPrefix: $script:why" }
    $excepts += ($full + '\')
}

$exacts = @()
foreach ($raw in $exactRaw) {
    $full = Resolve-AbsolutePath $raw
    if ($null -eq $full) { Reject "-ExactPath: $script:why" }
    $leaf = [System.IO.Path]::GetFileName($full)
    if (-not $leaf.Equals($ExeName, [System.StringComparison]::OrdinalIgnoreCase)) {
        Reject "-ExactPath apunta a '$leaf' y -ExeName es '$ExeName'"
    }
    $exacts += $full
}

$mode = if ($DryRun) { 'DRY-RUN, no se cierra nada' } else { 'cierre real' }
$filterText = @()
if ($AllInstances) {
    $filterText += 'TODAS las instancias'
    if ($helperNames.Count -gt 0) { $filterText += "auxiliares [$($helperNames -join ', ')]" }
    if ($helperPrefixes.Count -gt 0) { $filterText += "carpetas extra [$($helperPrefixes -join ', ')]" }
    if ($excepts.Count -gt 0) { $filterText += "excepto [$($excepts -join ', ')]" }
}
if ($prefixes.Count -gt 0) { $filterText += "prefijo [$($prefixes -join ', ')]" }
if ($exacts.Count -gt 0) { $filterText += "exacto [$($exacts -join ', ')]" }
$treeText = ''
if ($Tree) {
    $treeText = ' con -Tree'
    if ($allows.Count -gt 0) { $treeText += " (helpers permitidos [$($allows -join ', ')])" }
}
Write-Line "$ExeName por $($filterText -join ' + ')$treeText  ($mode)"

# --- Filtros ---

function Get-NormPath([string] $path) {
    try { return [System.IO.Path]::GetFullPath($path) } catch { return $path }
}

function Test-InList([string] $norm, [string[]] $folders) {
    foreach ($f in $folders) {
        if ($norm.StartsWith($f, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-Excepted([string] $path) {
    if ($excepts.Count -eq 0) { return $false }
    return (Test-InList (Get-NormPath $path) $excepts)
}

function Test-PathMatch([string] $path) {
    $norm = Get-NormPath $path
    foreach ($e in $exacts) {
        if ($norm.Equals($e, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return (Test-InList $norm $prefixes)
}

# Carpetas donde -Tree puede cerrar descendientes. En el modo por ruta es el filtro principal; con
# -AllInstances se fija antes de cada proceso (su carpeta + -HelperPrefix).
$script:treeScope = $null

# Un descendiente se cierra si esta en el filtro (o en el alcance fijado) o en un -TreeAllow, y no
# esta en un -ExceptPrefix.
function Test-TreeMatch([string] $path) {
    if (Test-Excepted $path) { return $false }
    $norm = Get-NormPath $path
    if ($null -ne $script:treeScope) {
        if (Test-InList $norm $script:treeScope) { return $true }
    } elseif (Test-PathMatch $path) {
        return $true
    }
    return (Test-InList $norm $allows)
}

# Carpeta de una instancia para buscar sus auxiliares (ver -AllInstances en la cabecera). Devuelve
# la carpeta con separador final, o $null con el motivo en $script:why.
function Get-InstanceFolder([string] $exePath) {
    $script:why = ''
    $exeDir = [System.IO.Path]::GetDirectoryName((Get-NormPath $exePath))
    $folder = $exeDir
    $dir = $exeDir
    for ($level = 0; $level -le 2 -and $dir; $level++) {
        $cache = Join-Path $dir 'CMakeCache.txt'
        if (Test-Path -LiteralPath $cache -PathType Leaf) {
            $srcRoot = $null
            try {
                $line = Select-String -LiteralPath $cache -Pattern '^CMAKE_HOME_DIRECTORY:INTERNAL=(.+)$' | Select-Object -First 1
                if ($line) { $srcRoot = $line.Matches[0].Groups[1].Value.Trim() }
            } catch { }
            if ($srcRoot) {
                $srcRootFull = $null
                try { $srcRootFull = [System.IO.Path]::GetFullPath($srcRoot.Replace('/', '\')).TrimEnd('\') } catch { }
                if ($srcRootFull -and (Test-Path -LiteralPath (Join-Path $srcRootFull 'CMakeLists.txt') -PathType Leaf) -and
                    ($dir + '\').StartsWith($srcRootFull + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $folder = $srcRootFull
                }
            }
            break
        }
        $dir = [System.IO.Path]::GetDirectoryName($dir)
    }
    $full = Resolve-AbsolutePath $folder
    if ($null -eq $full) { return $null }
    $why = Test-HelperFolder $full
    if ($why -ne '') { $script:why = $why; return $null }
    return ($full + '\')
}

# --- Consulta ---

try {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='$ExeName'")
} catch {
    Write-Line "no se pudo consultar Win32_Process ($($_.Exception.Message)); no se cierra nada."
    exit 0
}

if ($procs.Count -eq 0 -and -not ($AllInstances -and $helperNames.Count -gt 0 -and $helperPrefixes.Count -gt 0)) {
    Write-Line "no hay ningun $ExeName corriendo."
    exit 0
}

$allProcs = @()
if ($Tree) {
    try {
        $allProcs = @(Get-CimInstance Win32_Process)
    } catch {
        Write-Line "no se pudo listar los procesos para -Tree ($($_.Exception.Message)); no se cierra nada."
        exit 0
    }
}

# Descendientes de $root, en orden de recorrido. Cada uno: Proc, Depth, Action
# ('cerrar', 'fuera', 'sin-ruta', 'rama-viva'). Un hijo solo cuenta como tal si nacio despues que
# su padre: si el padre murio y su PID se reuso, el "hijo" es de otro.
function Get-Descendants($root) {
    $result = @()
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue(@{ Proc = $root; Depth = 0; Alive = $false })
    $seen = @{ ([int]$root.ProcessId) = $true }
    while ($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        $parent = $node.Proc
        foreach ($c in $allProcs) {
            $cid = [int]$c.ProcessId
            if ($c.ParentProcessId -ne $parent.ProcessId -or $seen.ContainsKey($cid)) { continue }
            if ($null -ne $parent.CreationDate -and $null -ne $c.CreationDate -and $c.CreationDate -lt $parent.CreationDate) { continue }
            $seen[$cid] = $true
            if ($node.Alive) {
                $action = 'rama-viva'
            } elseif (-not $c.ExecutablePath) {
                $action = 'sin-ruta'
            } elseif (Test-TreeMatch $c.ExecutablePath) {
                $action = 'cerrar'
            } else {
                $action = 'fuera'
            }
            $entry = @{ Proc = $c; Depth = $node.Depth + 1; Action = $action }
            $result += $entry
            $queue.Enqueue(@{ Proc = $c; Depth = $node.Depth + 1; Alive = ($action -ne 'cerrar') })
        }
    }
    return ,$result
}

# Cierra un proceso por PID, revalidando justo antes que siga siendo el mismo.
# Devuelve 'cerrado', 'no-cerrado' o 'ya-no-esta'.
function Close-ByPid($p, [string] $path) {
    $procId = [int]$p.ProcessId
    $again = $null
    try { $again = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" } catch { }
    if ($null -eq $again -or -not $again.ExecutablePath -or
        -not ($again.ExecutablePath.Equals($path, [System.StringComparison]::OrdinalIgnoreCase)) -or
        $again.CreationDate -ne $p.CreationDate) {
        return 'ya-no-esta'
    }
    try { Stop-Process -Id $procId -Force -ErrorAction Stop } catch { Write-Line "  Stop-Process PID ${procId}: $($_.Exception.Message)" }
    $alive = $null
    for ($i = 0; $i -lt 20; $i++) {
        $alive = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($null -eq $alive) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($null -eq $alive) { return 'cerrado' }
    return 'no-cerrado'
}

$script:closed = 0
$script:failed = 0
$script:wouldClose = 0
$script:left = 0
# PIDs ya tratados (cerrados o listados como tales), para que el barrido de auxiliares no los repita.
$script:handled = @{}

# Cierra (o lista, con -DryRun) un proceso que ya paso el filtro, y despues sus descendientes.
# $label es el prefijo de las lineas del log ('PID' o 'auxiliar PID').
function Close-Matched($p, [string] $path, [string] $label) {
    $procId = [int]$p.ProcessId
    $script:handled[$procId] = $true

    $desc = @()
    if ($Tree) {
        $live = @($allProcs | Where-Object { [int]$_.ProcessId -eq $procId })
        if ($live.Count -gt 0) { $desc = Get-Descendants $live[0] }
    }

    if ($DryRun) {
        Write-Line "$label $procId cerraria: $path"
        $script:wouldClose++
    } else {
        $r = Close-ByPid $p $path
        switch ($r) {
            'cerrado'    { Write-Line "$label $procId cerrado: $path"; $script:closed++ }
            'no-cerrado' { Write-Line "$label $procId NO SE PUDO CERRAR, sigue vivo: $path"; $script:failed++ }
            default      { Write-Line "$label $procId ya no es el mismo proceso (termino solo): no se toca." }
        }
    }

    # Descendientes: el padre se cierra primero para que no relance a sus hijos.
    foreach ($d in $desc) {
        $dp = $d.Proc
        $did = [int]$dp.ProcessId
        $indent = '  ' * $d.Depth
        $dpath = if ($dp.ExecutablePath) { $dp.ExecutablePath } else { '(ruta no legible)' }
        switch ($d.Action) {
            'fuera'     { Write-Line "${indent}descendiente PID $did fuera del prefijo y de -TreeAllow, se deja vivo: $dpath"; $script:left++; continue }
            'sin-ruta'  { Write-Line "${indent}descendiente PID $did sin ruta legible, se deja vivo"; $script:left++; continue }
            'rama-viva' { Write-Line "${indent}descendiente PID $did cuelga de uno que se deja vivo, no se toca: $dpath"; $script:left++; continue }
        }
        if ($d.Action -ne 'cerrar') { continue }
        $script:handled[$did] = $true
        if ($DryRun) {
            Write-Line "${indent}descendiente PID $did cerraria: $dpath"
            $script:wouldClose++
            continue
        }
        $r = Close-ByPid $dp $dp.ExecutablePath
        switch ($r) {
            'cerrado'    { Write-Line "${indent}descendiente PID $did cerrado: $dpath"; $script:closed++ }
            'no-cerrado' { Write-Line "${indent}descendiente PID $did NO SE PUDO CERRAR, sigue vivo: $dpath"; $script:failed++ }
            default      { Write-Line "${indent}descendiente PID $did ya no esta (termino con su padre)." }
        }
    }
}

if (-not $AllInstances) {
    # --- Modo por ruta (rev 1-2) ---
    foreach ($p in $procs) {
        $procId = [int]$p.ProcessId
        $path = $p.ExecutablePath
        if (-not $path) {
            Write-Line "PID $procId sin ExecutablePath legible (otra sesion o sin permisos): se deja vivo."
            $script:left++
            continue
        }
        if (-not (Test-PathMatch $path)) {
            Write-Line "PID $procId fuera del filtro, se deja vivo: $path"
            $script:left++
            continue
        }
        Close-Matched $p $path 'PID'
    }
} else {
    # --- Modo todas las instancias (rev 3) ---
    # Carpetas de auxiliares: las de cada instancia cerrada mas los -HelperPrefix.
    $helperFolders = @($helperPrefixes)
    foreach ($p in $procs) {
        $procId = [int]$p.ProcessId
        $path = $p.ExecutablePath
        if (-not $path) {
            Write-Line "PID $procId sin ExecutablePath legible (otra sesion o sin permisos): se deja vivo."
            $script:left++
            continue
        }
        if (Test-Excepted $path) {
            Write-Line "PID $procId en un -ExceptPrefix, se deja vivo: $path"
            $script:left++
            continue
        }
        $folder = Get-InstanceFolder $path
        $scope = @($helperPrefixes)
        if ($null -eq $folder) {
            Write-Line "PID $procId instancia en una carpeta que no pasa las guardas ($script:why): se cierra, pero no se buscan auxiliares ahi."
        } else {
            Write-Line "PID $procId instancia, carpeta de auxiliares: $folder"
            $scope += $folder
            if (-not ($helperFolders -contains $folder)) { $helperFolders += $folder }
        }
        $script:treeScope = $scope
        Close-Matched $p $path 'PID'
    }

    # Auxiliares: por nombre como primer filtro, decididos por carpeta. Van despues de las
    # instancias para que ninguna los relance.
    $script:treeScope = @($helperFolders)
    foreach ($hname in $helperNames) {
        $hprocs = @()
        try {
            $hprocs = @(Get-CimInstance Win32_Process -Filter "Name='$hname'")
        } catch {
            Write-Line "no se pudo consultar $hname ($($_.Exception.Message)); no se cierra ninguno."
            continue
        }
        foreach ($hp in $hprocs) {
            $hid = [int]$hp.ProcessId
            if ($script:handled.ContainsKey($hid)) { continue }
            $hpath = $hp.ExecutablePath
            if (-not $hpath) {
                Write-Line "auxiliar PID $hid ($hname) sin ExecutablePath legible: se deja vivo."
                $script:left++
                continue
            }
            if (Test-Excepted $hpath) {
                Write-Line "auxiliar PID $hid en un -ExceptPrefix, se deja vivo: $hpath"
                $script:left++
                continue
            }
            if (-not (Test-InList (Get-NormPath $hpath) $helperFolders)) {
                Write-Line "auxiliar PID $hid fuera de las carpetas de la app, se deja vivo: $hpath"
                $script:left++
                continue
            }
            Close-Matched $hp $hpath 'auxiliar PID'
        }
    }
    if ($procs.Count -eq 0) { Write-Line "no hay ningun $ExeName corriendo." }
}

if ($DryRun) {
    Write-Line "resumen (dry-run): cerraria $script:wouldClose, deja vivos $script:left."
} else {
    Write-Line "resumen: cerrados $script:closed, no se pudieron cerrar $script:failed, dejados vivos $script:left."
}
exit 0
