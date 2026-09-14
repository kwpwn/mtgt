# Run orchestrator as admin, capture output to log file
$logFile = Join-Path $PSScriptRoot "exploit_output.log"
$scriptDir = $PSScriptRoot

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Elevating to admin..."
    $cmd = "Set-Location '$scriptDir'; python orchestrator.py --shellcode calc 2>&1 | Tee-Object -FilePath '$logFile'; Read-Host 'Press Enter'"
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$cmd`"" -Verb RunAs
    Write-Host "Elevated window opened. Check $logFile for output."
    exit
}

Set-Location $scriptDir
Write-Host "Running as Administrator..."
python orchestrator.py --shellcode calc 2>&1 | Tee-Object -FilePath $logFile
Write-Host "`nOutput saved to: $logFile"
Read-Host "Press Enter to exit"
