<#
.SYNOPSIS
    Bump de version de LGA GateBouncer para publicar un release. Lo corre Lega cuando decide publicar:
    nunca se corre solo ni en cada cambio.
.DESCRIPTION
    Los dos numeros significan cosas distintas:
      - CMakeLists.txt (project(LGA_GateBouncer VERSION x.yy)): la ultima version PUBLICADA.
      - El primer "vX.YY:" de docs/ChangeLog.md: la version EN DESARROLLO, donde se juntan las entradas
        hasta el proximo release. Que el changelog vaya adelante es el estado normal.
    El bump sube CMakeLists.txt a la version del changelog. Despues se arma el instalador
    (instalador.bat --no-run), se revisa, y recien ahi se publica con publicar.ps1.

    Misma logica que el bump de Mighty Tools. Sin Python a proposito: el repo no tiene runtime propio.
    La version va de a centesimos (1.00, 1.01...): con otro formato el script falla. Sin consola
    interactiva, toda pregunta se contesta que no.
.PARAMETER Check
    No escribe nada: sale 0 si CMakeLists.txt, el changelog y docs/WhatsNew.md dicen lo mismo y el bump
    esta commiteado (listo para publicar), 1 si no. Lo usa publicar.ps1.
.PARAMETER Commit
    Commitea y pushea el bump sin preguntar.
.PARAMETER NoCommit
    Deja el bump sin commitear y no pregunta (tampoco ofrece armar el instalador).
.PARAMETER Installer
    Despues del push corre instalador.bat --no-run sin preguntar.
.PARAMETER NoInstaller
    No arma el instalador ni pregunta.
#>
param(
    [switch]$Check,
    [switch]$Commit,
    [switch]$NoCommit,
    [switch]$Installer,
    [switch]$NoInstaller
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$changelogPath = Join-Path $root 'docs\ChangeLog.md'
$whatsNewPath = Join-Path $root 'docs\WhatsNew.md'
$cmakePath = Join-Path $root 'CMakeLists.txt'
$expectedEmail = '176236735+legandrop@users.noreply.github.com'
$utf8 = New-Object System.Text.UTF8Encoding($false)

$headerPattern = '(?m)^v([0-9]+\.[0-9]+)\s*:'
$whatsNewPattern = '(?m)^##\s+v([0-9]+\.[0-9]+)\s*$'
$cmakePattern = 'project\(\s*LGA_GateBouncer\s+VERSION\s+([0-9]+\.[0-9]+)'

$commitMode = if ($NoCommit) { 'no' } elseif ($Commit) { 'yes' } else { 'ask' }
$installerMode = if ($NoInstaller) { 'no' } elseif ($Installer) { 'yes' } else { 'ask' }

function Get-Key([string]$version) {
    $parts = $version.Split('.')
    return [int]$parts[0] * 1000 + [int]$parts[1]
}

# Pregunta Y/N con una sola tecla, como `choice /C YN`. Sin consola interactiva contesta que no.
function Ask([string]$question) {
    if ([Console]::IsInputRedirected) {
        Write-Host "$question [Y,N]? N (sin consola)"
        return $false
    }
    while ($true) {
        Write-Host "$question [Y,N]? " -NoNewline
        $key = [Console]::ReadKey($true).KeyChar.ToString().ToUpper()
        if ($key -eq 'Y' -or $key -eq 'S') { Write-Host 'Y'; return $true }
        if ($key -eq 'N') { Write-Host 'N'; return $false }
        Write-Host ''
    }
}

# En PowerShell 5.1, con 'Stop', lo que git escribe por stderr se vuelve una excepcion: aca se decide
# por el codigo de salida.
function Invoke-Git {
    $ErrorActionPreference = 'Continue'
    $out = & git -C $root @args 2>&1 | ForEach-Object { "$_" }
    $script:gitExit = $LASTEXITCODE
    return $out
}

# Red: 3 reintentos cada 5 s (el firewall de la PC bloquea el primer intento de cada programa nuevo).
function Invoke-GitNet {
    for ($i = 1; $i -le 4; $i++) {
        $out = Invoke-Git @args
        if ($gitExit -eq 0) { return $out }
        if ($i -lt 4) { Write-Host "[bump_version] git $($args[0]) fallo (intento $i de 4); reintento en 5 s"; Start-Sleep -Seconds 5 }
    }
    return $out
}

try {
    $changelog = [IO.File]::ReadAllText($changelogPath, $utf8)
    $cmake = [IO.File]::ReadAllText($cmakePath, $utf8)
    $whatsNew = [IO.File]::ReadAllText($whatsNewPath, $utf8)

    $m = [regex]::Match($changelog, $headerPattern)
    if (-not $m.Success) { throw 'No se encontro un encabezado "vX.YY:" en docs/ChangeLog.md' }
    $changelogVersion = $m.Groups[1].Value
    $m = [regex]::Match($cmake, $cmakePattern)
    if (-not $m.Success) { throw 'No se encontro project(LGA_GateBouncer VERSION x.yy) en CMakeLists.txt' }
    $cmakeVersion = $m.Groups[1].Value
    $m = [regex]::Match($whatsNew, $whatsNewPattern)
    $whatsNewVersion = if ($m.Success) { $m.Groups[1].Value } else { 'ninguna' }

    foreach ($v in @($changelogVersion, $cmakeVersion)) {
        if ($v -notmatch '^[0-9]+\.[0-9]{2}$') {
            throw "La version '$v' no tiene dos decimales (se numera 1.00, 1.01...)"
        }
    }
    Write-Host "[bump_version] Publicada (CMakeLists.txt): $cmakeVersion | En desarrollo (changelog): $changelogVersion | WhatsNew: $whatsNewVersion"

    if ($Check) {
        if ($cmakeVersion -ne $changelogVersion) {
            Write-Host '[bump_version] ERROR: CMakeLists.txt y el changelog no dicen lo mismo: falta correr bump_version.bat y commitear.'
            exit 1
        }
        if ($whatsNewVersion -ne $changelogVersion) {
            Write-Host "[bump_version] ERROR: docs/WhatsNew.md no tiene arriba la seccion ## v$changelogVersion (tiene $whatsNewVersion)."
            exit 1
        }
        # Un bump hecho pero sin commitear no sirve para publicar: el tag apuntaria a otro estado.
        $null = Invoke-Git diff --quiet HEAD '--' CMakeLists.txt
        if ($gitExit -ne 0) {
            Write-Host "[bump_version] ERROR: el bump a $changelogVersion esta hecho pero sin commitear: commitearlo, o descartarlo con git checkout -- CMakeLists.txt y volver a correr bump_version.bat."
            exit 1
        }
        Write-Host "[bump_version] OK: todo en $changelogVersion."
        exit 0
    }

    # Antes de escribir nada, si se va a commitear: el bump sale de main al dia con origin, del changelog
    # commiteado (si no, se pushea un main donde CMakeLists.txt y el changelog no coinciden), de
    # CMakeLists.txt sin otros cambios (el commit lo lleva entero) y con la identidad de legandrop.
    if ($commitMode -ne 'no') {
        $branch = (Invoke-Git rev-parse --abbrev-ref HEAD | Out-String).Trim()
        if ($branch -ne 'main') { throw "La rama es '$branch': el bump se hace en main." }
        $out = Invoke-GitNet fetch -q origin main
        if ($gitExit -ne 0) { throw "No se pudo leer origin/main. $out" }
        $null = Invoke-Git merge-base --is-ancestor origin/main HEAD
        if ($gitExit -ne 0) { throw 'main esta atras de origin/main: hacer git pull antes del bump.' }
        $null = Invoke-Git diff --quiet HEAD '--' docs/ChangeLog.md docs/WhatsNew.md
        if ($gitExit -ne 0) { throw 'docs/ChangeLog.md o docs/WhatsNew.md tienen cambios sin commitear: commitearlos antes del bump.' }
        $null = Invoke-Git diff --quiet HEAD '--' CMakeLists.txt
        if ($gitExit -ne 0) { throw 'CMakeLists.txt tiene cambios sin commitear: commitearlos o descartarlos antes del bump (si son de un bump anterior sin commitear, alcanza con git checkout -- CMakeLists.txt y volver a correrlo).' }
        # GitHub atribuye por email: con otra identidad el commit queda fuera de la cuenta.
        $email = (Invoke-Git config user.email | Out-String).Trim()
        if ($email -ne $expectedEmail) { throw "git user.email es '$email' y se esperaba '$expectedEmail'." }
    }

    if ((Get-Key $changelogVersion) -lt (Get-Key $cmakeVersion)) {
        throw "El changelog (v$changelogVersion) esta por debajo de la version publicada ($cmakeVersion). Revisarlo a mano."
    }
    if ($whatsNewVersion -ne $changelogVersion) {
        Write-Host "[bump_version] AVISO: docs/WhatsNew.md no tiene la seccion ## v$changelogVersion (arriba tiene $whatsNewVersion): publicar.ps1 no va a dejar publicar sin notas."
    }

    if ($changelogVersion -eq $cmakeVersion) {
        Write-Host "[bump_version] CMakeLists.txt ya esta en ${cmakeVersion}: no hay version nueva que subir."
        Write-Host '               Para un release nuevo, el changelog tiene que abrir v<siguiente>: con sus entradas.'
    }
    else {
        $parts = $cmakeVersion.Split('.')
        $n = [int]$parts[0] * 100 + [int]$parts[1] + 1
        $next = '{0}.{1:D2}' -f [int][math]::Floor($n / 100), ($n % 100)
        if ($changelogVersion -ne $next) {
            Write-Host "[bump_version] AVISO: el changelog salta de $cmakeVersion a $changelogVersion (lo esperable era $next)."
            if (-not (Ask "Subir igual a $changelogVersion")) { throw 'Bump cancelado.' }
        }
        $newCmake = ([regex]$cmakePattern).Replace($cmake, { param($x) $x.Value.Substring(0, $x.Value.Length - $x.Groups[1].Value.Length) + $changelogVersion }, 1)
        [IO.File]::WriteAllText($cmakePath, $newCmake, $utf8)
        Write-Host "[bump_version] Bump: $cmakeVersion -> $changelogVersion"
    }
    $version = $changelogVersion

    # ---- Commit y push: el commit lleva SOLO CMakeLists.txt, nunca un `git add -A` que arrastre trabajo
    # en curso. El push lleva ademas los commits locales previos, que se listan antes.
    if ($commitMode -eq 'no') { Write-Host '[bump_version] Sin commit: el cambio queda en el arbol.'; exit 0 }
    $status = Invoke-Git status --porcelain '--' CMakeLists.txt
    if ($gitExit -ne 0) { throw "git status fallo: $status" }
    if (@($status | Where-Object { $_ -match '\S' }).Count -gt 0) {
        $ahead = @(Invoke-Git log '--format=  %h %s' origin/main..HEAD | Where-Object { $_ -match '\S' })
        if ($ahead.Count -gt 0) {
            Write-Host '[bump_version] El push lleva tambien estos commits locales que todavia no estan en origin:'
            $ahead | ForEach-Object { Write-Host $_ }
        }
        if ($commitMode -eq 'ask' -and -not (Ask "Commitear y pushear el bump a v$version")) {
            Write-Host '[bump_version] Commit omitido: el cambio queda en el arbol.'
            exit 0
        }
        $out = Invoke-Git add '--' CMakeLists.txt
        if ($gitExit -ne 0) { throw "git add fallo: $out" }
        $out = Invoke-Git commit -q -m "Version: bump a v$version" '--' CMakeLists.txt
        if ($gitExit -ne 0) { throw "Fallo el commit; el cambio queda stageado. $out" }
        Write-Host (Invoke-Git log -1 '--format=[bump_version] Commit %h: %s')
        $out = Invoke-GitNet push -q origin main
        if ($gitExit -ne 0) { throw "Fallo el push; el commit queda local. Revisar credenciales y reintentar a mano. $out" }
        Write-Host '[bump_version] Pusheado.'
    }
    else {
        Write-Host '[bump_version] No hay cambios de version para commitear.'
    }

    # ---- Instalador: instalador.bat --no-run lo arma sin publicar ni ejecutar nada. Publicar es aparte
    # (publicar.ps1), despues de revisar el resultado: nunca encadenado con la prueba.
    if ($installerMode -eq 'no') { exit 0 }
    if ($installerMode -eq 'ask' -and -not (Ask "Armar el instalador v$version (instalador.bat --no-run)")) {
        Write-Host '[bump_version] Instalador omitido. Para armarlo despues: instalador.bat --no-run'
        exit 0
    }
    & (Join-Path $root 'instalador.bat') --no-run
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host '[bump_version] Revisar el instalador y despues publicar con:'
        Write-Host '               powershell -NoProfile -ExecutionPolicy Bypass -File publicar.ps1'
    }
    exit $code
}
catch {
    Write-Host "[bump_version] ERROR: $($_.Exception.Message)"
    exit 1
}
