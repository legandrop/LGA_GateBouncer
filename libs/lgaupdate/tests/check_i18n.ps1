<#
.SYNOPSIS
    Confronta la tabla en castellano de src/LgaUpdateI18n.cpp con los textos traducibles de src/*.cpp: los tr() (con
    el contexto de la clase donde estan) y los QCoreApplication::translate("<contexto>", ...).
.DESCRIPTION
    Sale 0 si cada texto tiene su traduccion, la tabla no tiene claves que el codigo ya no usa y cada traduccion
    conserva los mismos %N, la misma cantidad de & (atajos) y las mismas etiquetas HTML que el ingles; 1 si no, con la
    lista. Un texto sin traduccion no rompe nada (sale en ingles), pero deja el cartel a medias en castellano. Solo
    lee archivos.

      powershell -NoProfile -ExecutionPolicy Bypass -File libs\lgaupdate\tests\check_i18n.ps1
#>
$ErrorActionPreference = 'Stop'
$lib = Split-Path -Parent $PSScriptRoot
$utf8 = New-Object System.Text.UTF8Encoding($false)

# Une literales C++ consecutivos ("a" "b") y resuelve los escapes que usa la biblioteca.
function Join-Literals([string]$chunk) {
    $parts = [regex]::Matches($chunk, '"((?:[^"\\]|\\.)*)"') | ForEach-Object { $_.Groups[1].Value }
    $text = ($parts -join '')
    return [regex]::Replace($text, '\\(.)', { param($m) switch ($m.Groups[1].Value) { 'n' { "`n" } default { $m.Groups[1].Value } } })
}

# Lo que tiene que coincidir entre ingles y castellano: los %N, la cantidad de & de atajo y las etiquetas HTML.
function Get-Shape([string]$text) {
    $places = ([regex]::Matches($text, '%\d') | ForEach-Object { $_.Value } | Sort-Object -Unique) -join ','
    $amps = ([regex]::Matches($text, '&(?!&)') | Measure-Object).Count
    $tags = ([regex]::Matches($text, '<[^>]+>') | ForEach-Object { $_.Value } | Sort-Object) -join ''
    return "$places|$amps|$tags"
}

$literals = '((?:"(?:[^"\\]|\\.)*"\s*)+)'
$used = @{}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $lib 'src') -Filter '*.cpp') {
    if ($file.Name -eq 'LgaUpdateI18n.cpp') { continue }
    $code = [IO.File]::ReadAllText($file.FullName, $utf8)
    # El contexto de un tr() es la clase de la funcion que lo contiene: la ultima definicion "Clase::metodo(" que
    # empieza en la columna 0 antes del tr().
    $definitions = [regex]::Matches($code, '(?m)^[A-Za-z][^\n;]*?\b(Lga\w+)::~?\w+\s*\(')
    foreach ($m in [regex]::Matches($code, '\btr\(\s*' + $literals)) {
        $context = 'LgaUpdateService'
        foreach ($d in $definitions) { if ($d.Index -lt $m.Index) { $context = $d.Groups[1].Value } else { break } }
        $used[$context + '|' + (Join-Literals $m.Groups[1].Value)] = $file.Name
    }
    foreach ($m in [regex]::Matches($code, 'QCoreApplication::translate\(\s*"([^"]+)"\s*,\s*' + $literals)) {
        $used[$m.Groups[1].Value + '|' + (Join-Literals $m.Groups[2].Value)] = $file.Name
    }
}

$table = [IO.File]::ReadAllText((Join-Path $lib 'src\LgaUpdateI18n.cpp'), $utf8)
$keys = @{}
foreach ($m in [regex]::Matches($table, '\bE\(\s*"([^"]+)"\s*,\s*' + $literals + ',\s*' + $literals + '\)')) {
    $keys[$m.Groups[1].Value + '|' + (Join-Literals $m.Groups[2].Value)] = Join-Literals $m.Groups[3].Value
}

$problems = 0
foreach ($k in $used.Keys) {
    if (-not $keys.ContainsKey($k)) { Write-Host "[check_i18n] SIN TRADUCCION ($($used[$k])): $($k.Replace("`n", '\n'))"; $problems++ }
}
foreach ($k in $keys.Keys) {
    if (-not $used.ContainsKey($k)) { Write-Host "[check_i18n] CLAVE QUE YA NO SE USA: $($k.Replace("`n", '\n'))"; $problems++; continue }
    $english = $k.Substring($k.IndexOf('|') + 1)
    if ((Get-Shape $english) -ne (Get-Shape $keys[$k])) {
        Write-Host "[check_i18n] DISTINTOS %N, & O ETIQUETAS: $($english.Replace("`n", '\n'))"
        $problems++
    }
}
Write-Host "[check_i18n] textos en el codigo: $($used.Count) | claves en la tabla: $($keys.Count)"
if ($problems) { exit 1 }
Write-Host '[check_i18n] OK'
exit 0
