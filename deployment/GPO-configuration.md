# GPO configuration (demo/lab reference)

- Object: GPO "Endpoint PCI Scanner – Startup"
- Scope: OU "Workstations/Finance" linking
- Startup script: deployment/Deploy-LightweightScanner.ps1
  (localscript copy needs elevated run; Domain Computers requires read on tool
   share, write on results share; machine startup rights sufficient)
- Alternative for large estates: immediate scheduled task at logon with a
  randomised 0–30-minute delay (perf to avoid thundering herd)
- Shares: FS01\pci-scanner-tools (read: Domain Computers)
          FS01\pci-scanner-results (modify: Domain Computers)
