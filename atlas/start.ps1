$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
Stop-Process -Name node -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-Process -FilePath "cmd.exe" -ArgumentList "/c","npx tsx services/shad/src/server.ts > shad.log 2>&1" -WorkingDirectory $root -WindowStyle Hidden
Start-Sleep -Seconds 4
Start-Process -FilePath "cmd.exe" -ArgumentList "/c","npx tsx services/command-gateway/src/server.ts > gw.log 2>&1" -WorkingDirectory $root -WindowStyle Hidden
Start-Sleep -Seconds 4
Start-Process -FilePath "cmd.exe" -ArgumentList "/c","npm run dev > vite.log 2>&1" -WorkingDirectory "$root\apps\shad-console" -WindowStyle Hidden
Start-Sleep -Seconds 6
Write-Host "Atlas started:"
Write-Host "  SHAD API:        http://localhost:4001"
Write-Host "  Command Gateway: http://localhost:4002"
Write-Host "  SHAD Console:    http://localhost:5173"