# ====================================================================
#  Windows Competition Security Hardening Script
#  Tested on Windows 10 / 11 / Server 2019 / Server 2022
#  Run as Administrator
# ====================================================================

# --- Helper Aliases ---
function glu { Get-LocalUser }
function slu { Set-LocalUser }
function algm { Add-LocalGroupMember }
function rnlu { Rename-LocalUser }

Write-Host "Starting Windows Hardening Process..." -ForegroundColor Cyan

# ====================================================================
# USER ACCOUNT MANAGEMENT
# ====================================================================

Write-Host "`n[+] Managing User Accounts..." -ForegroundColor Yellow

# List all users
Get-LocalUser

# List user names only
Get-LocalUser | Select-Object -ExpandProperty Name

# Example: Remove unauthorized user (replace <username> manually)
# Remove-LocalUser -Name "<username>"

# List admins
Get-LocalGroupMember -Group "Administrators"

# Example: Remove unauthorized admins
# Remove-LocalGroupMember -Group "Administrators" -Member "<username>"

# Example: Add required admins
# Add-LocalGroupMember -Group "Administrators" -Member "<username>"

# Example: Create new user
# New-LocalUser -Name "<username>" -NoPassword

# Change all passwords to CyberPatriot!
glu | slu -Password (ConvertTo-SecureString -AsPlainText "CyberPatriot!" -Force) -Verbose

# Force password expiration
glu | slu -PasswordNeverExpires $false

# Rename/disable Administrator and Guest
rnlu administrator nimda
Disable-LocalUser -Name "Administrator"
Disable-LocalUser -Name "Guest"
# Rename guest
# Rename-LocalUser -Name "Guest" -NewName "<newname>"

# ====================================================================
# SECURITY POLICY BASELINES
# ====================================================================

Write-Host "`n[+] Resetting Security Policy..." -ForegroundColor Yellow
secedit /configure /cfg $env:windir\inf\defltbase.inf /db defltbase.sdb /verbose

# Re-add users to Users group after reset
net localgroup users /add (glu)

# ====================================================================
# PASSWORD POLICY
# ====================================================================

Write-Host "`n[+] Configuring Password Policy..." -ForegroundColor Yellow
net accounts /maxpwage:40 /minpwage:10 /minpwlen:12 /uniquepw:10 /lockoutthreshold:5 /lockoutwindow:10 /lockoutduration:10

secedit /export /cfg "secpol.inf"
(Get-Content "secpol.inf") -replace 'PasswordComplexity.*', 'PasswordComplexity = 1' | Set-Content "secpol.inf"
(Get-Content "secpol.inf") -replace 'ClearTextPassword.*', 'ClearTextPassword = 0' | Set-Content "secpol.inf"
echo y | secedit /configure /db "C:\Windows\Security\local.sdb" /cfg "secpol.inf" /overwrite

# ====================================================================
# LOCAL SECURITY OPTIONS
# ====================================================================

Write-Host "`n[+] Applying Local Security Registry Tweaks..." -ForegroundColor Yellow

# Limit blank passwords
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# Prevent unauthorized drivers
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1

# Restrict CDROM/Floppy access
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateFloppies" -Value 1 -Force

# Interactive logon controls
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "Authorized Use Only." -Force

# Network access restrictions
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 1

# Shutdown/Recovery protections
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1

# ====================================================================
# WINDOWS FIREWALL
# ====================================================================

Write-Host "`n[+] Configuring Windows Firewall..." -ForegroundColor Yellow

Set-NetFirewallProfile -All -Enabled True
Set-NetFirewallProfile -All -DefaultInboundAction Block
Set-NetFirewallProfile -All -NotifyOnListen False
Set-NetFirewallProfile -All -AllowLocalFirewallRules False
Set-NetFirewallProfile -All -AllowLocalIPsecRules False
Set-NetFirewallProfile -All -LogFileName "%SystemRoot%\System32\logfiles\firewall\allprofilesfw.log"
Set-NetFirewallProfile -All -LogMaxSizeKilobytes 16384
Set-NetFirewallProfile -All -LogBlocked True
Set-NetFirewallProfile -All -LogAllowed True

# ====================================================================
# WINDOWS DEFENDER
# ====================================================================

Write-Host "`n[+] Configuring Windows Defender..." -ForegroundColor Yellow

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealTimeMonitoring" -Value 0
Set-MpPreference -DisableRealtimeMonitoring $false

# Clear Defender exclusions
(Get-MpPreference).ExclusionPath | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionPath $_ }
(Get-MpPreference).ExclusionExtension | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ } 2>$null

# Set default actions for threats
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Name "High" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Name "Moderate" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Name "Low" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Name "ZeroDay" -Value 0

# ====================================================================
# SERVICES HARDENING
# ====================================================================

Write-Host "`n[+] Disabling Insecure or Unused Services..." -ForegroundColor Yellow

$servicesToDisable = @(
"BTAGService","bthserv","Browser","MapsBroker","lfsvc","IISADMIN","irmon","lltdsvc","LxssManager",
"FTPSVC","MSiSCSI","sshd","PNRPsvc","p2psvc","p2pimsvc","PNRPAutoReg","Spooler","wercplsupport",
"RasAuto","SessionEnv","TermService","UmRdpService","RpcLocator","RemoteRegistry","RemoteAccess",
"LanmanServer","simptcp","SNMP","sacsvr","SSDPSRV","upnphost","WMSvc","WerSvc","Wecsvc",
"WMPNetworkSvc","icssvc","WpnService","PushToInstall","WinRM","W3SVC","XboxGipSvc","XblAuthManager",
"XblGameSave","XboxNetApiSvc","NetTcpPortSharing","DNS","LPDsvc","RasMan","SNMPTRAP","TlntSvr",
"TapiSrv","WebClient","LanmanWorkstation"
)

foreach ($svc in $servicesToDisable) {
    Write-Host "Disabling service: $svc"
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# ====================================================================
# WINDOWS UPDATE
# ====================================================================

Write-Host "`n[+] Configuring Windows Update..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AllowMUUpdateService" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4
Restart-Service -Name wuauserv
Set-Service -Name "wuauserv" -StartupType "Automatic"
Start-Service -Name "wuauserv"

Write-Host "`n[+] Installing Windows Updates..." -ForegroundColor Yellow
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSWindowsUpdate -Force
Set-ExecutionPolicy RemoteSigned -Force
Import-Module PSWindowsUpdate -Force
Install-WindowsUpdate -ForceDownload -ForceInstall -Confirm:$False

# ====================================================================
# FINAL STEPS
# ====================================================================

Write-Host "`n[+] Running Windows Defender Full Scan..." -ForegroundColor Yellow
Start-MpScan -ScanType QuickScan

Write-Host "`n[+] System Hardening Completed Successfully!" -ForegroundColor Green
Write-Host "Rebooting system now..." -ForegroundColor Yellow
 Restart-Computer -Force








































#STOP














<#
.SYNOPSIS
Windows 11 Local Security Hardening Script
.DESCRIPTION
Performs account, policy, firewall, service, and Defender configuration
to align with CyberPatriot-style baseline hardening.
Author: ChatGPT GPT-5
#>

# ================================
#   0.  Setup
# ================================
$Log = "C:\Hardening.log"
Start-Transcript -Path $Log -Append
Write-Host "==== HARDENING SCRIPT STARTED $(Get-Date) ====" -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force
$ErrorActionPreference = 'SilentlyContinue'

function Safe-Exec($cmd, $desc) {
    Write-Host "[*] $desc" -ForegroundColor Yellow
    try { Invoke-Expression $cmd; Write-Host "    ✔ Success" -ForegroundColor Green }
    catch { Write-Host "    ✖ Failed: $_" -ForegroundColor Red }
}

# ================================
#   1.  Account Management
# ================================
Write-Host "`n=== USER & GROUP MANAGEMENT ===" -ForegroundColor Cyan

# Read authorized users list if exists
$readme = "C:\AuthorizedUsers.txt"
$AuthorizedUsers = @()
if (Test-Path $readme) { $AuthorizedUsers = Get-Content $readme }

# List all users
$AllUsers = Get-LocalUser | Select-Object -ExpandProperty Name
Write-Host "Local users: $($AllUsers -join ', ')"

# Remove unauthorized users
foreach ($user in $AllUsers) {
    if ($AuthorizedUsers -notcontains $user -and $user -ne "Administrator" -and $user -ne "Guest") {
        Safe-Exec "Remove-LocalUser -Name '$user'" "Removing unauthorized user: $user"
    }
}

# Disable Guest & built-in Administrator
Safe-Exec 'Disable-LocalUser -Name "Administrator"' "Disable built-in Administrator"
Safe-Exec 'Disable-LocalUser -Name "Guest"' "Disable Guest account"

# Rename built-in accounts
if (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue) {
    Safe-Exec 'Rename-LocalUser -Name "Administrator" -NewName "nimda"' "Rename Administrator to nimda"
}
if (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue) {
    Safe-Exec 'Rename-LocalUser -Name "Guest" -NewName "visitor"' "Rename Guest to visitor"
}

# Enforce strong passwords
Safe-Exec 'Get-LocalUser | ForEach-Object { $_ | Set-LocalUser -Password (ConvertTo-SecureString "CyberPatriot!" -AsPlainText -Force) -PasswordNeverExpires $false }' "Reset and expire all user passwords"

# ================================
#   2.  Local Security Policy
# ================================
Write-Host "`n=== SECURITY POLICY ===" -ForegroundColor Cyan
$SecInf = "$env:TEMP\secpol.inf"
Safe-Exec 'secedit /export /cfg "$SecInf"' "Export current security policy"

$policyChanges = @{
    "PasswordComplexity"              = "PasswordComplexity = 1"
    "ClearTextPassword"               = "ClearTextPassword = 0"
    "SeDenyNetworkLogonRight"         = "SeDenyNetworkLogonRight = Guest"
    "SeTrustedCredManAccessPrivilege" = "SeTrustedCredManAccessPrivilege = Administrator"
    "SeSecurityPrivilege"             = "SeSecurityPrivilege = *S-1-5-32-544"
}

foreach ($kvp in $policyChanges.GetEnumerator()) {
    (Get-Content $SecInf) -replace "$($kvp.Key).*", $kvp.Value | Set-Content $SecInf
}
Safe-Exec 'echo y | secedit /configure /db "C:\Windows\Security\local.sdb" /cfg "$SecInf" /overwrite' "Import modified security policy"

# ================================
#   3.  Registry-based Hardening
# ================================
Write-Host "`n=== REGISTRY HARDENING ===" -ForegroundColor Cyan

$regSettings = @(
    'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1',
    'Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1',
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -Value 0',
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "Authorized Use Only."',
    'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 1'
)
foreach ($cmd in $regSettings) { Safe-Exec $cmd "Applying registry hardening setting" }

# ================================
#   4.  Firewall Configuration
# ================================
Write-Host "`n=== FIREWALL CONFIGURATION ===" -ForegroundColor Cyan

Safe-Exec 'Set-NetFirewallProfile -All -Enabled True' "Enable Windows Firewall"
Safe-Exec 'Set-NetFirewallProfile -All -DefaultInboundAction Block' "Block inbound connections"
Safe-Exec 'Set-NetFirewallProfile -All -LogBlocked True -LogAllowed True' "Enable firewall logging"

# ================================
#   5.  Windows Defender
# ================================
Write-Host "`n=== WINDOWS DEFENDER ===" -ForegroundColor Cyan

Safe-Exec 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0' "Enable Windows Defender"
Safe-Exec 'Set-MpPreference -DisableRealtimeMonitoring $false' "Enable real-time monitoring"
Safe-Exec '(Get-MpPreference).ExclusionPath | ForEach-Object { Remove-MpPreference -ExclusionPath $_ }' "Clear Defender exclusions"

# ================================
#   6.  Service Hardening
# ================================
Write-Host "`n=== SERVICE HARDENING ===" -ForegroundColor Cyan

$DisableServices = @(
 "BTAGService","bthserv","Browser","MapsBroker","lfsvc","IISADMIN","irmon","lltdsvc",
 "LxssManager","FTPSVC","MSiSCSI","sshd","PNRPsvc","p2psvc","p2pimsvc","PNRPAutoReg",
 "Spooler","wercplsupport","RasAuto","SessionEnv","TermService","UmRdpService",
 "RpcLocator","RemoteRegistry","RemoteAccess","simptcp","SNMP","sacsvr","SSDPSRV",
 "upnphost","WMSvc","WerSvc","Wecsvc","WMPNetworkSvc","icssvc","WpnService",
 "PushToInstall","WinRM","W3SVC","XboxGipSvc","XblAuthManager","XblGameSave","XboxNetApiSvc",
 "NetTcpPortSharing","DNS","LPDsvc","RasMan","SNMPTRAP","TlntSvr","TapiSrv","WebClient"
)
foreach ($svc in $DisableServices) {
    Safe-Exec "Stop-Service -Name '$svc' -Force -ErrorAction SilentlyContinue" "Stop service $svc"
    Safe-Exec "Set-Service -Name '$svc' -StartupType Disabled" "Disable service $svc"
}

# ================================
#   7.  Updates & Maintenance
# ================================
Write-Host "`n=== WINDOWS UPDATE CONFIGURATION ===" -ForegroundColor Cyan

Safe-Exec 'Set-Service -Name "wuauserv" -StartupType Automatic' "Set Windows Update to Automatic"
Safe-Exec 'Start-Service -Name "wuauserv"' "Start Windows Update service"
Safe-Exec 'Install-PackageProvider -Name NuGet -Force' "Ensure NuGet provider"
Safe-Exec 'Install-Module -Name PSWindowsUpdate -Force' "Install PSWindowsUpdate module"
Safe-Exec 'Import-Module PSWindowsUpdate -Force' "Import PSWindowsUpdate"
Safe-Exec 'Install-WindowsUpdate -ForceDownload -ForceInstall -Confirm:$False' "Apply all Windows Updates"

# ================================
#   8.  Final System Checks
# ================================
Write-Host "`n=== FINAL CHECKS ===" -ForegroundColor Cyan
Safe-Exec 'Start-MpScan -ScanType QuickScan' "Run Windows Defender Quick Scan"
Safe-Exec 'netstat -aon | findstr LISTENING' "List listening ports"
Safe-Exec 'Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch "Microsoft" } | Select TaskName,TaskPath,State' "List non-Microsoft scheduled tasks"

Write-Host "``n==== HARDENING COMPLETE ====" -ForegroundColor Green
Stop-Transcript
