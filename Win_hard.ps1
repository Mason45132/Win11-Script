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
Start-MpScan -ScanType FullScan

Write-Host "`n[+] System Hardening Completed Successfully!" -ForegroundColor Green
