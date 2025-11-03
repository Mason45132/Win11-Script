# ====================================================================
#  Windows Server 2022 Security Hardening Script
#  Author: ChatGPT (GPT-5)
#  For Competition / Baseline Server Lockdown
#  Run as Administrator
# ====================================================================

Write-Host "=== Windows Server 2022 Hardening Script Starting ===" -ForegroundColor Cyan

# --- Helper Aliases ---
function glu { Get-LocalUser }
function slu { Set-LocalUser }
function algm { Add-LocalGroupMember }
function rnlu { Rename-LocalUser }

# ====================================================================
# USER ACCOUNT MANAGEMENT
# ====================================================================

Write-Host "`n[+] Managing Local Users and Admins..." -ForegroundColor Yellow

# List all local users
Get-LocalUser

# Force password reset for all local users
glu | slu -Password (ConvertTo-SecureString -AsPlainText "CyberPatriot!" -Force) -Verbose
glu | slu -PasswordNeverExpires $false

# Rename and disable built-in Administrator and Guest
Try { rnlu administrator nimda } Catch {}
Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

# ====================================================================
# SECURITY POLICY BASELINES
# ====================================================================

Write-Host "`n[+] Resetting Local Security Policy..." -ForegroundColor Yellow
secedit /configure /cfg $env:windir\inf\defltbase.inf /db defltbase.sdb /verbose

# Add users back to "Users" group after reset
net localgroup users /add (glu)

# ====================================================================
# PASSWORD AND ACCOUNT POLICY
# ====================================================================

Write-Host "`n[+] Configuring Account and Password Policies..." -ForegroundColor Yellow

net accounts /maxpwage:40 /minpwage:10 /minpwlen:12 /uniquepw:10 /lockoutthreshold:5 /lockoutwindow:10 /lockoutduration:10

secedit /export /cfg "C:\secpol.inf"
(Get-Content "C:\secpol.inf") -replace 'PasswordComplexity.*', 'PasswordComplexity = 1' | Set-Content "C:\secpol.inf"
(Get-Content "C:\secpol.inf") -replace 'ClearTextPassword.*', 'ClearTextPassword = 0' | Set-Content "C:\secpol.inf"
echo y | secedit /configure /db "C:\Windows\Security\local.sdb" /cfg "C:\secpol.inf" /overwrite

# ====================================================================
# LOCAL SECURITY OPTIONS (REGISTRY)
# ====================================================================

Write-Host "`n[+] Applying Security Registry Configurations..." -ForegroundColor Yellow

# Disable blank passwords remotely
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# Require Ctrl+Alt+Del
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -Value 0

# Hide last logged user
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1

# Add logon message
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "Authorized Use Only." -Force

# Restrict anonymous access
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

# Clear virtual memory pagefile at shutdown
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1

# Disable shutdown without login
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0 -Force

# ====================================================================
# WINDOWS FIREWALL CONFIGURATION
# ====================================================================

Write-Host "`n[+] Configuring Windows Firewall..." -ForegroundColor Yellow

Set-NetFirewallProfile -All -Enabled True
Set-NetFirewallProfile -All -DefaultInboundAction Block
Set-NetFirewallProfile -All -NotifyOnListen False
Set-NetFirewallProfile -All -AllowLocalFirewallRules False
Set-NetFirewallProfile -All -AllowLocalIPsecRules False
Set-NetFirewallProfile -All -LogFileName "%SystemRoot%\System32\logfiles\firewall\serverfw.log"
Set-NetFirewallProfile -All -LogMaxSizeKilobytes 16384
Set-NetFirewallProfile -All -LogBlocked True
Set-NetFirewallProfile -All -LogAllowed True

# ====================================================================
# WINDOWS DEFENDER CONFIGURATION
# ====================================================================

Write-Host "`n[+] Configuring Windows Defender..." -ForegroundColor Yellow

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealTimeMonitoring" -Value 0
Set-MpPreference -DisableRealtimeMonitoring $false

# Clear any exclusions
(Get-MpPreference).ExclusionPath | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionPath $_ }
(Get-MpPreference).ExclusionExtension | Where-Object { $_ } | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ } 2>$null

# Ensure Defender threat action defaults
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Force | Out-Null
foreach ($level in "High","Moderate","Low","ZeroDay") {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -Name $level -Value 0
}

# Start and set Defender to automatic
Start-Service -Name "WinDefend"
Set-Service -Name "WinDefend" -StartupType Automatic

# ====================================================================
# CRITICAL SERVICE LOCKDOWN
# ====================================================================

Write-Host "`n[+] Disabling Unnecessary or Vulnerable Services..." -ForegroundColor Yellow

$servicesToDisable = @(
"BTAGService","bthserv","Browser","MapsBroker","lfsvc","IISADMIN","FTPSVC","sshd",
"PNRPsvc","p2psvc","p2pimsvc","PNRPAutoReg","Spooler","RemoteRegistry",
"RemoteAccess","TermService","UmRdpService","RpcLocator","SNMP","SNMPTRAP",
"SSDPSRV","upnphost","WinRM","WMSvc","W3SVC","Telnet","RasMan","LPDsvc",
"WebClient","XboxGipSvc","XblAuthManager","XblGameSave","XboxNetApiSvc"
)

foreach ($svc in $servicesToDisable) {
    Write-Host "Disabling service: $svc"
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# ====================================================================
# WINDOWS UPDATE CONFIGURATION
# ====================================================================

Write-Host "`n[+] Enabling Windows Updates..." -ForegroundColor Yellow

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AllowMUUpdateService" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4
Restart-Service -Name wuauserv
Set-Service -Name "wuauserv" -StartupType "Automatic"
Start-Service -Name "wuauserv"

# Optional: Install Windows Updates
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSWindowsUpdate -Force
Set-ExecutionPolicy RemoteSigned -Force
Import-Module PSWindowsUpdate -Force
Install-WindowsUpdate -ForceDownload -ForceInstall -Confirm:$False

# ====================================================================
# NETWORK & SYSTEM AUDITING
# ====================================================================

Write-Host "`n[+] Enabling Auditing and Network Security..." -ForegroundColor Yellow

# Enable audit policies
auditpol /set /category:* /success:enable /failure:enable

# Disable LANMAN hash storage
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1

# Block anonymous enumeration of SAM & shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 1

# ====================================================================
# VALIDATION
# ====================================================================

Write-Host "`n[+] Validating Security Settings..." -ForegroundColor Yellow

Write-Host "Defender Realtime Protection: " -NoNewline
(Get-MpComputerStatus).RealTimeProtectionEnabled

Write-Host "Firewall Profiles Enabled: " -NoNewline
(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled)

Write-Host "Auditing Enabled: " -NoNewline
auditpol /get /category:*

# ====================================================================
# FINAL DEFENDER SCAN
# ====================================================================

Write-Host "`n[+] Running Full Defender Scan..." -ForegroundColor Yellow
Start-MpScan -ScanType FullScan

Write-Host "`n=== Windows Server 2022 Hardening Complete ===" -ForegroundColor Green
