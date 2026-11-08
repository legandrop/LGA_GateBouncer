# Confronta los textos de la interfaz con la tabla de espanol (PowerShell 5.1, sin Python).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\qa\check_i18n.ps1 [-Root <carpeta que tiene src>]
#
# Saca de src\ (menos src\qa y menos el mecanismo de I18n) los literales de I18n::tr("...") y de
# I18n::trc("contexto", "..."), los junta con la clave que usa la tabla ("texto" o "contexto|texto"),
# y los compara con las entradas E("clave", "traduccion") de src\i18n_es.cpp.
#   FALTAN : claves que el codigo usa y la tabla no tiene (en espanol saldrian en ingles).
#   SOBRAN : entradas de la tabla que ningun codigo usa (texto muerto).
# Sale con 0 si no falta ni sobra nada; con 1 si hay alguno. No compila ni ejecuta nada.
#
# Excepciones de claves armadas en tiempo de ejecucion (no son un literal en el codigo): ninguna hoy.
# Si alguna vez una clave se arma con datos, se declara aca en $runtimeKeys con el motivo.
# Las llamadas I18n::tr(<variable>) fuera de core\I18n.* tambien se listan (DINAMICAS) y cuentan como
# falla: todo texto visible debe ser un literal para que este script lo vea.

param(
    # Raiz del arbol a revisar (la que tiene src). Por defecto la del repo; sirve para probar el script sobre una copia.
    [string]$Root
)

$ErrorActionPreference = 'Stop'

$runtimeKeys = @()   # claves de la tabla que el codigo arma al vuelo (con el motivo al lado)

if ([string]::IsNullOrEmpty($Root)) {
    $Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$root = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
$src = Join-Path $root 'src'
$tablePath = Join-Path $src 'i18n_es.cpp'
$utf8 = New-Object System.Text.UTF8Encoding($false)

# Quita los comentarios (// y /* */) sin tocar lo que hay adentro de un literal de texto o de caracter.
$stripPattern = '"(?:[^"\\\r\n]|\\.)*"|''(?:[^''\\\r\n]|\\.)*''|//[^\r\n]*|/\*[\s\S]*?\*/'
$stripEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    if ($m.Value.StartsWith('/')) {
        # Conserva los saltos de linea para no mover nada, y reemplaza el resto por un espacio.
        return ' ' + ([regex]::Replace($m.Value, '[^\r\n]', ''))
    }
    return $m.Value
}
function Remove-Comments([string]$text) {
    return [regex]::Replace($text, $stripPattern, $stripEvaluator)
}

# Decodifica los escapes de un literal de C++ (lo que hay entre las comillas).
function Unescape-Cpp([string]$raw) {
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $raw.Length) {
        $c = $raw[$i]
        if ($c -ne '\') { [void]$sb.Append($c); $i++; continue }
        $i++
        if ($i -ge $raw.Length) { break }
        $e = $raw[$i]
        switch ($e) {
            'n' { [void]$sb.Append("`n") }
            't' { [void]$sb.Append("`t") }
            'r' { [void]$sb.Append("`r") }
            '"' { [void]$sb.Append('"') }
            "'" { [void]$sb.Append("'") }
            '\' { [void]$sb.Append('\') }
            'u' { [void]$sb.Append([char][Convert]::ToInt32($raw.Substring($i + 1, 4), 16)); $i += 4 }
            default { [void]$sb.Append('\'); [void]$sb.Append($e) }
        }
        $i++
    }
    return $sb.ToString()
}

$lit = '"(?:[^"\\]|\\.)*"'
$lits = "(?:$lit\s*)+"

# Une literales contiguos ("a" "b") y los decodifica.
function Join-Literals([string]$run) {
    $text = ''
    foreach ($m in [regex]::Matches($run, $lit)) {
        $text += Unescape-Cpp $m.Value.Substring(1, $m.Value.Length - 2)
    }
    return $text
}

# ---------------------------------------------------------------- lo que usa el codigo
$used = @{}          # clave -> "archivo:linea" de la primera vez
$dynamic = New-Object System.Collections.ArrayList
$files = Get-ChildItem -Path $src -Recurse -Include *.cpp, *.h, *.mm |
    Where-Object {
        $_.FullName -ne $tablePath -and
        $_.Name -notin @('i18n.h', 'i18n.cpp')
    }
foreach ($file in $files) {
    $clean = Remove-Comments ([System.IO.File]::ReadAllText($file.FullName, $utf8))
    $rel = $file.FullName.Substring($root.Length + 1)
    $lineOf = { param($index) 1 + ([regex]::Matches($clean.Substring(0, $index), "`n")).Count }

    foreach ($m in [regex]::Matches($clean, "I18n::trc\(\s*($lit)\s*,\s*($lits)")) {
        $context = Unescape-Cpp $m.Groups[1].Value.Substring(1, $m.Groups[1].Value.Length - 2)
        $key = $context + '|' + (Join-Literals $m.Groups[2].Value)
        if (-not $used.ContainsKey($key)) { $used[$key] = "${rel}:" + (& $lineOf $m.Index) }
    }
    foreach ($m in [regex]::Matches($clean, "I18n::tr\(\s*($lits)")) {
        $key = Join-Literals $m.Groups[1].Value
        if (-not $used.ContainsKey($key)) { $used[$key] = "${rel}:" + (& $lineOf $m.Index) }
    }
    # Llamadas cuyo primer argumento no es un literal: no se pueden confrontar.
    foreach ($m in [regex]::Matches($clean, 'I18n::trc?\(\s*([^"\s])')) {
        [void]$dynamic.Add("${rel}:" + (& $lineOf $m.Index))
    }
}

# ---------------------------------------------------------------- lo que tiene la tabla
$table = @{}
$tableText = Remove-Comments ([System.IO.File]::ReadAllText($tablePath, $utf8))
$duplicates = New-Object System.Collections.ArrayList
foreach ($m in [regex]::Matches($tableText, "\bE\(\s*($lits)\s*,\s*($lits)\)")) {
    $key = Join-Literals $m.Groups[1].Value
    if ($table.ContainsKey($key)) { [void]$duplicates.Add($key) }
    $table[$key] = Join-Literals $m.Groups[2].Value
}

$missing = @($used.Keys | Where-Object { -not $table.ContainsKey($_) } | Sort-Object)
$unused = @($table.Keys | Where-Object { -not $used.ContainsKey($_) -and ($runtimeKeys -notcontains $_) } | Sort-Object)

Write-Host ("check_i18n: {0} textos distintos en el codigo, {1} entradas en la tabla" -f $used.Count, $table.Count)
if ($missing.Count -gt 0) {
    Write-Host ("FALTAN {0} (el codigo los usa y la tabla no):" -f $missing.Count)
    foreach ($k in $missing) { Write-Host ("  [{0}] {1}" -f $used[$k], ($k -replace "`n", '\n')) }
}
if ($unused.Count -gt 0) {
    Write-Host ("SOBRAN {0} (la tabla los tiene y ningun codigo los usa):" -f $unused.Count)
    foreach ($k in $unused) { Write-Host ("  {0}" -f ($k -replace "`n", '\n')) }
}
if ($dynamic.Count -gt 0) {
    Write-Host ("DINAMICAS {0} (I18n::tr sin un literal; no se pueden confrontar):" -f $dynamic.Count)
    foreach ($d in $dynamic) { Write-Host ("  {0}" -f $d) }
}
if ($duplicates.Count -gt 0) {
    Write-Host ("REPETIDAS {0} (la misma clave dos veces en la tabla):" -f $duplicates.Count)
    foreach ($d in $duplicates) { Write-Host ("  {0}" -f ($d -replace "`n", '\n')) }
}
Write-Host ("check_i18n: faltantes={0} sobrantes={1} dinamicas={2} repetidas={3}" -f $missing.Count, $unused.Count, $dynamic.Count, $duplicates.Count)
if ($missing.Count -gt 0 -or $unused.Count -gt 0 -or $dynamic.Count -gt 0 -or $duplicates.Count -gt 0) { exit 1 }
exit 0
