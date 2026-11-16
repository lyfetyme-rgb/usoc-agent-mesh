# Fails if docs drift from the code. Read-only.
# Checks the things that have actually drifted before: test counts and env
# var names. Exit 1 on any stale token.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root

$Fail = $false
$files = @()
foreach ($p in @("README.md", "SECURITY.md", "docs\architecture.md", "toolbox")) {
    if (Test-Path $p) {
        $files += Get-ChildItem -Path $p -Recurse -File -Include *.md,*.ps1,*.py,*.toml
    }
}

$stale = @(
    "89 tests",
    "176 tests",
    "176 passed",
    "AGENT_ATLASSIAN_BRIDGE=",
    "cyber_strike",
    "cyber strike"
)

$staleHits = 0
foreach ($token in $stale) {
    $hits = $files | Where-Object { $_.Name -ne "doc_consistency.ps1" } | Select-String -Pattern ([regex]::Escape($token)) -CaseSensitive:$false
    foreach ($h in $hits) {
        if ($h.Line -match "renamed to") { continue }  # historical record, not a live claim
        $staleHits++
        Write-Host "STALE: $($h.Path):$($h.LineNumber)  '$($h.Line.Trim())'" -ForegroundColor Red
    }
}
if ($staleHits -gt 0) { $Fail = $true }

if (-not $Fail) {
    $readmeMatch = Select-String -Path README.md -Pattern "(\d+) tests" | Select-Object -First 1
    $archMatch = Select-String -Path "docs\architecture.md" -Pattern "(\d+) tests" | Select-Object -First 1
    if ($readmeMatch -and $archMatch) {
        $a = $readmeMatch.Matches.Groups[1].Value
        $b = $archMatch.Matches.Groups[1].Value
        if ($a -ne $b) {
            $Fail = $true
            Write-Host "DRIFT: README says $a tests, architecture.md says $b" -ForegroundColor Red
        } else {
            Write-Host "doc consistency: PASS ($a tests)" -ForegroundColor Green
        }
    }
}

if ($Fail) { exit 1 } else { exit 0 }
