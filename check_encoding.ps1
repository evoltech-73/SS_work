$ErrorActionPreference = 'Stop'

$path = Join-Path $PSScriptRoot 'ss_presentation.html'
$bytes = [IO.File]::ReadAllBytes($path)
$hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
$utf8Strict = [Text.UTF8Encoding]::new($false, $true)
$text = $utf8Strict.GetString($bytes)
$scanText = [regex]::Replace($text, "data:image/[^`"']+", 'data:image/...')

# Keep this script ASCII-only. The code points below are common mojibake
# characters produced when UTF-8 Japanese text is misread as Shift-JIS.
$suspiciousChars = @(
    0xFFFD, # replacement character
    0x7E67, # mojibake marker
    0x7E3A,
    0x96B1,
    0x83A8,
    0x8B41,
    0x870A,
    0x8816,
    0x90B1,
    0x8373
)

$hits = @()
foreach ($codePoint in $suspiciousChars) {
    $char = [char]$codePoint
    if ($scanText.Contains($char)) {
        $hits += ('U+{0:X4}' -f $codePoint)
    }
}

$suspiciousAscii = @('E?', '?E', ',E', 'Ebr>', 'E/h', 'E/li', 'E/p', 'E/span', 'E/div')
foreach ($pattern in $suspiciousAscii) {
    if ($scanText.Contains($pattern)) {
        $hits += $pattern
    }
}

$brokenClosingTags = [regex]::Matches($scanText, '[\u3040-\u30FF\u3400-\u9FFF]E/(h[1-6]|p|li|span|div)')
foreach ($match in $brokenClosingTags) {
    $hits += "broken closing tag near: $($match.Value)"
}

Write-Host "UTF-8 BOM: $hasBom"
Write-Host "Suspicious mojibake patterns: $($hits.Count)"

if (-not $hasBom) {
    throw 'ss_presentation.html is not saved with UTF-8 BOM.'
}

if ($hits.Count -gt 0) {
    throw "Suspicious mojibake patterns found: $($hits -join ', ')"
}

if ($text -notmatch '<meta\s+charset="UTF-8"\s*/?>') {
    throw 'ss_presentation.html is missing <meta charset="UTF-8">'
}
