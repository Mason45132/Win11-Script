<#
Generate-ReadME-TestScript.ps1
Author: ChatGPT
Purpose: Find ReadME.html on Desktop, extract human-readable text, pattern-match likely tasks,
         and produce a test PowerShell script (ReadME-Test-Script.ps1) containing commented
         code snippets that would accomplish those tasks. Nothing is executed.
Notes: - Run this in a controlled VM. - Review the produced test script before running any commands.
#>

# 1) Locate ReadME.html on Desktop (search recursively)
$desktop = [Environment]::GetFolderPath('Desktop')
$readmeFile = Get-ChildItem -Path $desktop -Filter 'ReadME.html' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $readmeFile) {
    Write-Host "No ReadME.html found on Desktop." -ForegroundColor Yellow
    return
}

Write-Host "Found ReadME.html at: $($readmeFile.FullName)" -ForegroundColor Green

# 2) Read raw HTML
$html = Get-Content -Path $readmeFile.FullName -Raw -ErrorAction Stop

# 3) Strip tags to get readable text (simple approach)
#    (not perfect HTML parsing, but fine for extracting instructions)
$plainText = [regex]::Replace($html, '<script.*?>.*?</script>', '', 'Singleline,IgnoreCase')
$plainText = [regex]::Replace($plainText, '<style.*?>.*?</style>', '', 'Singleline,IgnoreCase')
$plainText = [regex]::Replace($plainText, '<[^>]+>', ' ')
# Normalize whitespace and split into lines
$plainText = ($plainText -replace '\s+', ' ').Trim()
$lines = $plainText -split '([\.!\?]\s+)|(\r\n)|(\n)|(;)' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

# 4) Define patterns and corresponding snippet templates (commented)
$patterns = @(
    @{ rx = [regex]'(?i)\b(mkdir|create (directory|folder)|create folder|make directory)\b'; snippet = @'
# Create directory (example)
# $target = "C:\path\to\new-folder"
# New-Item -Path $target -ItemType Directory -Force
'@ },
    @{ rx = [regex]'(?i)\b(copy|cp|move|mv)\b'; snippet = @'
# Copy or move files
# Copy-Item -Path "C:\source\file.txt" -Destination "C:\dest\file.txt" -Force
# Move-Item -Path "C:\source\file.txt" -Destination "C:\dest\file.txt"
'@ },
    @{ rx = [regex]'(?i)\b(download|download from|fetch|wget|curl|invoke-webrequest)\b'; snippet = @'
# Download file example (Invoke-WebRequest)
# $url = "https://example.com/file.zip"
# $out = "$env:USERPROFILE\Desktop\file.zip"
# Invoke-WebRequest -Uri $url -OutFile $out
'@ },
    @{ rx = [regex]'(?i)\b(unzip|extract|expand-archive|tar\b|7-zip|7z)\b'; snippet = @'
# Extract archive examples
# Expand-Archive -Path "$env:USERPROFILE\Desktop\file.zip" -DestinationPath "$env:USERPROFILE\Desktop\extracted" -Force
# tar -xf file.tar.gz  # in environments that support tar
# 7z x file.zip         # if 7z is installed
'@ },
    @{ rx = [regex]'(?i)\b(start-process|run|execute|launch)\b'; snippet = @'
# Start / run a program
# Start-Process -FilePath "C:\path\to\installer.exe" -ArgumentList "/S" -Wait
# & "C:\path\to\script.ps1"   # run a script (if allowed)
'@ },
    @{ rx = [regex]'(?i)\b(set|environment variable|env var|setx)\b'; snippet = @'
# Set an environment variable (user scope)
# setx MY_VAR "my value"
# To set for current session:
# $env:MY_VAR = "my value"
'@ },
    @{ rx = [regex]'(?i)\b(git\b|clone|checkout|commit|pull|push)\b'; snippet = @'
# Git examples
# git clone https://github.com/owner/repo.git
# cd repo
# git checkout branch-name
'@ },
    @{ rx = [regex]'(?i)\b(npm\b|npm install|node\b|yarn)\b'; snippet = @'
# Node / npm examples
# npm install
# npm install -g some-package
# node index.js
'@ },
    @{ rx = [regex]'(?i)\b(pip\b|python\b|venv|virtualenv)\b'; snippet = @'
# Python examples
# python -m venv .venv
# .\.venv\Scripts\Activate.ps1
# pip install -r requirements.txt
# python script.py
'@ },
    @{ rx = [regex]'(?i)\b(service|start-service|stop-service|sc )\b'; snippet = @'
# Windows service examples
# Start-Service -Name "ServiceName"
# Stop-Service -Name "ServiceName"
# sc.exe query "ServiceName"
'@ },
    @{ rx = [regex]'(?i)\b(task scheduler|schtasks|schedule)\b'; snippet = @'
# Task scheduling (example)
# schtasks /Create /SC ONCE /TN "TaskName" /TR "C:\path\to\program.exe" /ST 12:00
'@ },
    @{ rx = [regex]'(?i)\b(chmod\b|linux permission|sudo)\b'; snippet = @'
# Permission / sudo examples (Linux-ish commands; adapt if WSL)
# chmod +x ./script.sh
# sudo apt update
'@ }
)

# 5) Build output script content
$outputPath = Join-Path -Path $desktop -ChildPath 'ReadME-Test-Script.ps1'
$header = @"
<#
ReadME-Test-Script.ps1
Auto-generated from ReadME.html on $([datetime]::Now)
This file contains commented PowerShell snippets that correspond to detected instructions.
ALL LINES ARE COMMENTED OUT. Review and uncomment only the commands you trust.
#>

"@


$body = New-Object System.Text.StringBuilder
$body.AppendLine($header) | Out-Null

$matchedAny = $false

# Examine each line for patterns and append matching snippets
foreach ($line in $lines) {
    foreach ($p in $patterns) {
        if ($p.rx.IsMatch($line)) {
            $matchedAny = $true
            $body.AppendLine("# ---- Detected instruction fragment:") | Out-Null
            $body.AppendLine("# $line") | Out-Null
            $body.AppendLine($p.snippet) | Out-Null
            break
        }
    }
}

# If nothing matched, create a helpful fallback: include several common templates
if (-not $matchedAny) {
    $body.AppendLine("# No explicit recognized task keywords were found in ReadME.html.") | Out-Null
    $body.AppendLine("# Below are general templates you can adapt based on the README content:") | Out-Null

    $generic = @'
# Example: Create a directory
# $target = "$env:USERPROFILE\Desktop\example-folder"
# New-Item -Path $target -ItemType Directory -Force

# Example: Download a file
# $url = "https://example.com/file.zip"
# $out = "$env:USERPROFILE\Desktop\file.zip"
# Invoke-WebRequest -Uri $url -OutFile $out

# Example: Extract a zip file
# Expand-Archive -Path $out -DestinationPath "$env:USERPROFILE\Desktop\extracted" -Force

# Example: Run an installer (silent if supported)
# Start-Process -FilePath "$env:USERPROFILE\Desktop\installer.exe" -ArgumentList "/S" -Wait

# Example: Git clone
# git clone https://github.com/owner/repo.git "$env:USERPROFILE\Desktop\repo"

# Example: Install Python requirements
# python -m venv .venv
# .\.venv\Scripts\Activate.ps1
# pip install -r requirements.txt
'@

    $body.AppendLine($generic) | Out-Null
}

# Also append the original plain text chunk for manual review
$body.AppendLine("# ---------- Extracted text from ReadME.html (for reference) ----------") | Out-Null
$body.AppendLine("# NOTE: This section is for your review. It is not code to run.") | Out-Null
foreach ($chunk in $lines) {
    $safeLine = $chunk -replace "'", "''"
    $body.AppendLine("# $safeLine") | Out-Null
}
$body.AppendLine("# -------------------------------------------------------------------") | Out-Null

# Write file
try {
    $body.ToString() | Out-File -FilePath $outputPath -Encoding UTF8 -Force
    Write-Host "Test script created at: $outputPath" -ForegroundColor Green
    Write-Host "Open it, review the commented commands, then uncomment and run commands you trust." -ForegroundColor Cyan
} catch {
    Write-Host "Failed to write test script: $_" -ForegroundColor Red
}
