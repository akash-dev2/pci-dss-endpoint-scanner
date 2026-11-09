# Deploy-LightweightScanner.ps1
# Computer startup script (Computer Configuration -> Policies -> Windows Settings
# -> Scripts -> Startup). Copies the current scanner from the tool share, runs the
# scan, uploads JSONL results to the per-host results directory, writes a marker.
#
$ToolShare   = "\\FS01\pci-scanner-tools"
$ResultsShare= "\\FS01\pci-scanner-results"
$ScanRoot    = "C:\Assets"
$LocalDir    = "C:\ProgramData\PciScanner"
$Version     = "iin_rules-v1.0"

try {
    New-Item -ItemType Directory -Force -Path $LocalDir | Out-Null

    Copy-Item -Force -Path (Join-Path $ToolShare 'lightweight_pci_scanner.py') $LocalDir
    Copy-Item -Force -Path (Join-Path $ToolShare ("$Version.json")) (Join-Path $LocalDir 'iin_rules-v1.0.json')

    $resultsDir = Join-Path $ResultsShare $env:COMPUTERNAME
    New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

    $out = Join-Path $resultsDir "scan_results.jsonl"
    & python (Join-Path $LocalDir 'lightweight_pci_scanner.py') $ScanRoot `
      --config (Join-Path $ToolShare 'gpo_condition.json') `
      --out $out 2>> (Join-Path $resultsDir "stderr.log")

    Write-Output "done" | Out-File -FilePath (Join-Path $resultsDir '.complete') -Encoding ascii
} catch {
    Write-Output $_.ToString() | Out-File (Join-Path (Join-Path $ResultsShare $env:COMPUTERNAME) 'error.log') -Encoding ascii
}
