param(
    [switch]$Docker,
    [switch]$Verify
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$argList = @("scripts/start_all_services.js")
if ($Docker) { $argList += "--docker" }
if ($Verify) { $argList += "--verify" }

& node @argList
exit $LASTEXITCODE
