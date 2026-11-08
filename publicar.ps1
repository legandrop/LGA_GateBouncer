# Publica el instalador ya armado por instalador.bat como release de GitHub de este mismo repo (público), con sus notas
# What's new, y le avisa al manifiesto de versiones de LGA (legandrop/LGA_Updates) para que las copias instaladas se
# actualicen solas. No compila nada: primero instalador.bat --no-run, se revisa el resultado, y recién después esto.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File publicar.ps1 [-Yes]
#
# -Yes no pregunta antes de publicar (sí corren todos los controles).
param([switch]$Yes)
# Continue: en PowerShell 5.1 el stderr redirigido de git y gh se vuelve error y cortaría con Stop. Cada paso se
# controla a mano por su código de salida.
$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$repo = 'legandrop/LGA_GateBouncer'
Set-Location -LiteralPath $root

function Fail([string]$why) { Write-Host "ERROR: $why"; exit 1 }

# Red: 3 reintentos cada 5 s (el firewall de la PC bloquea el primer intento de cada programa nuevo).
function Retry([string]$what, [scriptblock]$action) {
    for ($i = 1; $i -le 4; $i++) {
        & $action
        if ($LASTEXITCODE -eq 0) { return }
        if ($i -lt 4) { Write-Host "  $what falló (intento $i de 4); reintento en 5 s"; Start-Sleep -Seconds 5 }
    }
    Fail "$what falló cuatro veces."
}

# ---- versión y archivos
$line = Select-String -LiteralPath (Join-Path $root 'CMakeLists.txt') -Pattern '^project\(LGA_GateBouncer VERSION (\S+)' | Select-Object -First 1
if (-not $line) { Fail 'no se encontró la versión en CMakeLists.txt.' }
$version = $line.Matches[0].Groups[1].Value
$tag = "v$version"
$installerDir = if ($env:GATEBOUNCER_INSTALLER_DIR) { $env:GATEBOUNCER_INSTALLER_DIR } else { Join-Path $root 'installer' }
$setup = Join-Path $installerDir "LGA_GateBouncer_Setup_v$version.exe"
$sums = Join-Path $installerDir 'SHA256SUMS'
if (-not (Test-Path -LiteralPath $setup)) { Fail "no está $setup. Correr instalador.bat --no-run." }
if (-not (Test-Path -LiteralPath $sums)) { Fail "no está $sums." }
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $setup).Hash.ToLower()
if ((Get-Content -LiteralPath $sums -Raw) -notmatch [regex]::Escape($hash)) { Fail 'SHA256SUMS no corresponde al instalador.' }
Write-Host "Versión $version · $setup"
# CMakeLists.txt, el changelog y las notas tienen que decir lo mismo, con el bump commiteado (bump_version.bat).
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'tools\bump_version.ps1') -Check
if ($LASTEXITCODE -ne 0) { Fail 'la versión no está lista para publicar: correr bump_version.bat.' }

# ---- el repo: main, limpio y publicado
if ((git rev-parse --abbrev-ref HEAD) -ne 'main') { Fail 'no estoy en main.' }
if (git status --porcelain) { Fail 'hay cambios sin commitear.' }
Retry 'git fetch' { git fetch -q origin }
if ((git rev-parse HEAD) -ne (git rev-parse origin/main)) { Fail 'HEAD no es origin/main: pushear (o pullear) antes de publicar.' }
Retry 'gh auth status' { gh auth status *> $null }
if (git tag --list $tag) { Fail "el tag $tag ya existe en este clon." }
$remoteTag = $null
Retry 'git ls-remote' { $script:remoteTag = git ls-remote --tags origin "refs/tags/$tag" }
if ($remoteTag) { Fail "el tag $tag ya existe en origin." }
# El instalador tiene que salir de este commit: el exe se armó después del último commit.
$commitTime = [DateTimeOffset]::FromUnixTimeSeconds([int64](git log -1 --format=%ct)).LocalDateTime
if ((Get-Item -LiteralPath $setup).LastWriteTime -lt $commitTime) { Fail 'el instalador es anterior al último commit: volver a correr instalador.bat.' }

# ---- notas What's new (la lógica vive en LGA_RepoTools)
$repoTools = if ($env:LGA_REPOTOOLS) { $env:LGA_REPOTOOLS } else { Join-Path (Split-Path $root -Parent) 'LGA_RepoTools' }
$wn = Join-Path $repoTools 'WhatsNew_Win\whats_new_release.bat'
$wnFile = Join-Path $root 'docs\WhatsNew.md'
if (-not (Test-Path -LiteralPath $wn)) { Fail "no está $wn." }
$checkArgs = @('check', $wnFile, $version)
if ($Yes) { $checkArgs += '--yes' }
& $wn @checkArgs
if ($LASTEXITCODE -ne 0) { Fail "las notas de $tag faltan o no pasan el control." }

if (-not $Yes) {
    $answer = Read-Host "Publicar $tag en $repo? (s/n)"
    if ($answer -ne 's') { Write-Host 'No se publicó nada.'; exit 0 }
}

# ---- tag, release, notas y manifiesto
# Si algo falla después del tag, se dice cómo dejar todo limpio para reintentar (nada se borra solo).
$cleanup = @(
    "  gh release delete $tag --repo $repo --yes",
    "  git push origin :refs/tags/$tag",
    "  git tag -d $tag"
)
function FailAfterTag([string]$why) {
    Write-Host "ERROR: $why"
    Write-Host 'Para dejarlo limpio y volver a publicar (lo que no exista da un error inofensivo):'
    $cleanup | ForEach-Object { Write-Host $_ }
    exit 1
}
git tag -a $tag -m "Release $tag"
if ($LASTEXITCODE -ne 0) { Fail "no se pudo crear el tag $tag." }
$pushed = $false
for ($i = 1; $i -le 4 -and -not $pushed; $i++) {
    git push -q origin $tag
    $pushed = $LASTEXITCODE -eq 0
    if (-not $pushed -and $i -lt 4) { Write-Host "  push del tag falló (intento $i de 4); reintento en 5 s"; Start-Sleep -Seconds 5 }
}
if (-not $pushed) { FailAfterTag "no se pudo subir el tag $tag." }
# Reintentos idempotentes: si un intento anterior llegó a crear el release, se completan los archivos en vez de crearlo
# de nuevo.
$released = $false
for ($i = 1; $i -le 4 -and -not $released; $i++) {
    gh release view $tag --repo $repo *> $null
    if ($LASTEXITCODE -eq 0) { gh release upload $tag $setup $sums --repo $repo --clobber }
    else { gh release create $tag $setup $sums --repo $repo --verify-tag --title $tag --notes "Release $tag" }
    $released = $LASTEXITCODE -eq 0
    if (-not $released -and $i -lt 4) { Write-Host "  release falló (intento $i de 4); reintento en 5 s"; Start-Sleep -Seconds 5 }
}
if (-not $released) { FailAfterTag "no se pudo crear el release $tag." }
& $wn publish $wnFile $version $repo $tag
if ($LASTEXITCODE -ne 0) {
    Write-Host "AVISO: el release está publicado pero fallaron las notas. Reintentar con:"
    Write-Host "  `"$wn`" publish `"$wnFile`" $version $repo $tag"
    exit 1
}
# Las notas dejan WHATS_NEW.md en la raíz del repo con un commit: se trae para no divergir.
Retry 'git pull' { git pull -q --ff-only origin main }
gh workflow run refresh_versions.yml --repo legandrop/LGA_Updates *> $null
if ($LASTEXITCODE -eq 0) { Write-Host 'Manifiesto de versiones: refresco disparado.' }
else { Write-Host 'AVISO: no se pudo disparar el refresco del manifiesto; el cron lo levanta en 30 min.' }
Write-Host "Publicado: https://github.com/$repo/releases/tag/$tag"
