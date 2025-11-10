# ====================================================================
#  Windows Server 2022 Company Policy Compliance Script
#  Author: ChatGPT (GPT-5)
#  NOTE: Does NOT add or remove any users or groups
# ====================================================================

Write-Host "=== Starting Company Policy Compliance Configuration ===" -ForegroundColor Cyan

# ====================================================================
# SYSTEM VALIDATION
# ====================================================================

Write-Host "`n[+] Validating OS Version..." -ForegroundColor Yellow
$osVersion = (Get-CimInstance Win32_OperatingSystem).Caption
if ($osVersion -notmatch "Windows Server 2022") {
    Write-Warning "This system is not running Windows Server 2022. Current version: $osVersion"
} else {
    Write-Host "Verified: Windows Server 2022 detected."
}

# ====================================================================
# MICROSOFT DEFENDER INSTALLATION & CONFIGURATION
# ====================================================================

Write-Host "`n[+] Checking Microsoft Defender Installation..." -ForegroundColor Yellow

$defenderFeature = Get-WindowsFeature -Name "Windows-Defender" -ErrorAction SilentlyContinue

if (-not $defenderFeature -or $defenderFeature.Installed -eq $false) {
    Write-Host "Microsoft Defender not found. Attempting to install..."

    try {
        Install-WindowsFeature -Name "Windows-Defender" -IncludeAllSubFeature -IncludeManagementTools -ErrorAction Stop
        Install-WindowsFeature -Name "Windows-Defender-Features" -IncludeAllSubFeature -ErrorAction Stop
        Install-WindowsFeature -Name "Windows-Defender-GUI" -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Local installation source not found. You may need to install from the Windows Server 2022 ISO."

        $isoPath = Read-Host "Enter the path to your Windows Server 2022 ISO or mounted drive (e.g. D:\sources\sxs)"
        if (Test-Path $isoPath) {
            Write-Host "Attempting Defender installation from source: $isoPath"
            Install-WindowsFeature -Name "Windows-Defender" -Source $isoPath -IncludeAllSubFeature -IncludeManagementTools
            Install-WindowsFeature -Name "Windows-Defender-Features" -Source $isoPath -IncludeAllSubFeature
        } else {
            Write-Warning "Invalid source path or ISO not mounted. Please verify and rerun the script."
        }
    }
} else {
    Write-Host "Microsoft Defender is already installed."
}

# Verify Defender service
$service = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Warning "Defender service not found even after install. The feature may require a reboot."
} else {
    Start-Service -Name WinDefend -ErrorAction SilentlyContinue
    Set-Service -Name WinDefend -StartupType Automatic
    Write-Host "Microsoft Defender service started and set to automatic."
}

# Test WMI availability before calling Defender cmdlets
$defenderClass = Get-CimClass -Namespace "root\Microsoft\Windows\Defender" -ClassName "MSFT_MpPreference" -ErrorAction SilentlyContinue
if ($defenderClass) {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent 1 -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
    Write-Host "Microsoft Defender configuration applied."
} else {
    Write-Warning "Defender WMI interface not available yet. A reboot may be required to finalize Defender installation."
}

# ====================================================================
# DEFAULT APPLICATIONS
# ====================================================================

Write-Host "`n[+] Configuring Default Web Browser (Chrome)..." -ForegroundColor Yellow

$chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
if (Test-Path $chromePath) {
    Write-Host "Chrome found. Setting as default web browser..."
    Start-Process "cmd" -ArgumentList "/c start ms-settings:defaultapps" -WindowStyle Hidden
    Write-Host "Please verify Chrome is set as the default browser in Default Apps."
} else {
    Write-Warning "Chrome not found at expected path: $chromePath. Please install the latest stable version."
}

# ====================================================================
# VERIFY BUSINESS SOFTWARE
# ====================================================================

Write-Host "`n[+] Checking Required Business Software..." -ForegroundColor Yellow

$apps = @("Notepad++", "PuTTY", "WinRAR")

foreach ($app in $apps) {
    $installed = Get-Package | Where-Object { $_.Name -like "*$app*" }
    if ($installed) {
        Write-Host "$app is installed."
    } else {
        Write-Warning "$app not found. Please reinstall it."
    }
}

Write-Host "Reminder: Do NOT purchase a WinRAR license." -ForegroundColor Magenta

# ====================================================================
# SMB CONFIGURATION
# ====================================================================

Write-Host "`n[+] Validating SMB Configuration..." -ForegroundColor Yellow

$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($smb1.State -eq "Enabled") {
    Write-Warning "SMBv1 is enabled. It is insecure — consider disabling it if not required for legacy support."
} else {
    Write-Host "SMBv1 is disabled (recommended)."
}

$smbCompression = Get-SmbServerConfiguration | Select-Object EnableSMBCompression
if ($smbCompression.EnableSMBCompression -eq $false) {
    Write-Warning "SMB Compression is disabled — enabling it per policy..."
    Set-SmbServerConfiguration -EnableSMBCompression $true -Force
} else {
    Write-Host "SMB Compression is enabled."
}

$todoShare = Get-SmbShare | Where-Object { $_.Name -eq "TODOLIST" }
if ($todoShare) {
    Write-Host "Verified TODOLIST share exists for C:\TODO."
} else {
    Write-Warning "TODOLIST share not found. It should point to C:\TODO."
}

if (Test-Path "C:\TODO") {
    Write-Host "C:\TODO directory exists."
    if (Test-Path "C:\TODO\TODO.txt") {
        Write-Host "Found TODO file inside directory."
    } else {
        Write-Warning "TODO file missing inside C:\TODO."
    }
} else {
    Write-Warning "C:\TODO directory missing. Do NOT delete or rename if created later."
}

# ====================================================================
# FIREWALL AND UPDATES
# ====================================================================

Write-Host "`n[+] Verifying Firewall and Updates..." -ForegroundColor Yellow

Set-NetFirewallProfile -All -Enabled True
Set-NetFirewallProfile -All -DefaultInboundAction Block
Set-NetFirewallProfile -All -DefaultOutboundAction Allow
Write-Host "Firewall enabled for all profiles."

Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv
Write-Host "Windows Update service enabled."

# ====================================================================
# SECURITY POLICIES
# ====================================================================

Write-Host "`n[+] Applying Security Policy Settings..." -ForegroundColor Yellow

net accounts /maxpwage:40 /minpwlen:10 /lockoutthreshold:5 /lockoutwindow:10 /lockoutduration:10

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# ====================================================================
# VALIDATION OUTPUT
# ====================================================================

Write-Host "`n[+] Final Compliance Validation:" -ForegroundColor Yellow

if (Get-CimClass -Namespace "root\Microsoft\Windows\Defender" -ClassName "MSFT_MpComputerStatus" -ErrorAction SilentlyContinue) {
    Write-Host "Microsoft Defender Status:"
    (Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntispywareEnabled)
} else {
    Write-Warning "Microsoft Defender validation skipped (WMI not ready or feature missing)."
}

Write-Host "`nFirewall Profiles:"
Get-NetFirewallProfile | Select-Object Name, Enabled

Write-Host "`nSMB Configuration:"
Get-SmbServerConfiguration | Select-Object EnableSMBCompression, EnableSMB2Protocol

Write-Host "`nInstalled Software:"
Get-Package | Where-Object { $_.Name -match "Chrome|Notepad|PuTTY|WinRAR" } | Select-Object Name, Version

Write-Host "`n[✔] Policy Compliance Script Complete." -ForegroundColor Green
Write-Host "Rebooting system now..." -ForegroundColor Yellow 
Restart-Computer -Force