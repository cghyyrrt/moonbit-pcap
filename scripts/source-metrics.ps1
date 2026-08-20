$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$sourceRoots = @(
  (Join-Path $repoRoot 'src'),
  (Join-Path $repoRoot 'cmd')
)

foreach ($root in $sourceRoots) {
  if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Missing source root: $root"
  }
}

$files = foreach ($root in $sourceRoots) {
  Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.mbt' |
    Where-Object { $_.FullName -notmatch '[\\/]_build[\\/]' }
}

$total = 0
$production = 0
$tests = 0
$nonEmpty = 0
$code = 0

foreach ($file in $files) {
  $lines = @(Get-Content -LiteralPath $file.FullName)
  $count = $lines.Count
  $total += $count
  if ($file.Name -match '_test\.mbt$') { $tests += $count } else { $production += $count }
  foreach ($line in $lines) {
    if (-not [string]::IsNullOrWhiteSpace($line)) {
      $nonEmpty++
      $trimmed = $line.Trim()
      if (-not $trimmed.StartsWith('//')) { $code++ }
    }
  }
}

Write-Output "Handwritten MoonBit source metrics"
Write-Output "Files: $($files.Count)"
Write-Output "Total lines: $total"
Write-Output "Production lines: $production"
Write-Output "Test lines: $tests"
Write-Output "Non-empty lines: $nonEmpty"
Write-Output "Code lines: $code"
