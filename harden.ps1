# ===== Variables Section Start =====
$MaxPasswordAge = 60  # Maximum password age in days
$TempPassword = '1CyberPatriot!' # Temporary password for user accounts

# Color variables
$HeaderColor = "Cyan"            # Color for headers
$PromptColor = "Yellow"          # Color for prompts
$EmphasizedNameColor = "Green"   # Color for emphasized names
$KeptLineColor = "DarkYellow"    # Color for kept lines
$RemovedLineColor = "Red"        # Color for removed lines
$WarningColor = "Red"            # Color for warnings
# ===== Variables Section End =====

# Check for admin rights and relaunch as admin if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Script is not running as administrator. Relaunching as admin..." -ForegroundColor $WarningColor
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
# Display the computer's hostname
Write-Host "Computer Name: $env:COMPUTERNAME" -ForegroundColor $HeaderColor

# Display the Windows version
Write-Host "Windows Version:" -ForegroundColor $HeaderColor
Get-ComputerInfo | Select-Object -Property WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
Write-Host "Script Run Time: $(Get-Date)" -ForegroundColor $HeaderColor

# Define menu options
$menuOptions = @(
    "Document the system",
    "Enable updates",
    "User Auditing",
    "Account Policies",
    "Local Policies",
    "Defensive Countermeasures",
    "Uncategorized OS Settings",
    "Service Auditing",
    "OS Updates",
    "Application Updates",
    "Prohibited Files",
    "Unwanted Software",
    "Malware",
    "Application Security Settings",
    "Exit"
)

# Define functions for each option
function Document-System {
    Write-Host "`n--- Starting: Document the system ---`n" -ForegroundColor $HeaderColor

    # Detect the current user's desktop folder
    $desktopFolder = [Environment]::GetFolderPath("Desktop")
    $docsFolder = Join-Path -Path $desktopFolder -ChildPath "DOCS"

    # Create the DOCS folder if it does not already exist
    if (-not (Test-Path -Path $docsFolder)) {
        Write-Host "Creating DOCS folder at: $docsFolder" -ForegroundColor $EmphasizedNameColor
        New-Item -Path $docsFolder -ItemType Directory | Out-Null
    } else {
        Write-Host "DOCS folder already exists at: $docsFolder" -ForegroundColor $KeptLineColor
    }

    # Document local users
    $localUsersFile = Join-Path -Path $docsFolder -ChildPath "LocalUsers.txt"
    Write-Host "Documenting local users to: $localUsersFile" -ForegroundColor $PromptColor
    try {
        Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize | Out-String | Set-Content -Path $localUsersFile
        Write-Host "Local users documented successfully." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to document local users: $($_.Exception.Message)" -ForegroundColor $WarningColor
    }

    # Document administrators
    $administratorsFile = Join-Path -Path $docsFolder -ChildPath "administrators.txt"
    Write-Host "Documenting administrators to: $administratorsFile" -ForegroundColor $PromptColor
    try {
        Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass | Format-Table -AutoSize | Out-String | Set-Content -Path $administratorsFile
        Write-Host "Administrators documented successfully." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to document administrators: $($_.Exception.Message)" -ForegroundColor $WarningColor
    }

    # Document installed programs
    $programsFile = Join-Path -Path $docsFolder -ChildPath "programs.txt"
    Write-Host "Documenting installed programs to: $programsFile" -ForegroundColor $PromptColor
    try {
        Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Format-Table -AutoSize | Out-String | Set-Content -Path $programsFile
        Write-Host "Installed programs documented successfully." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to document installed programs: $($_.Exception.Message)" -ForegroundColor $WarningColor
    }

    # Document running services
    $servicesFile = Join-Path -Path $docsFolder -ChildPath "services.txt"
    Write-Host "Documenting running services to: $servicesFile" -ForegroundColor $PromptColor
    try {
        Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName, StartType | Format-Table -AutoSize | Out-String | Set-Content -Path $servicesFile
        Write-Host "Running services documented successfully." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to document running services: $($_.Exception.Message)" -ForegroundColor $WarningColor
    }

    # Document installed features
    $featuresFile = Join-Path -Path $docsFolder -ChildPath "features.txt"
    Write-Host "Documenting installed features to: $featuresFile" -ForegroundColor $PromptColor
    try {
        $features = dism /online /get-features /format:table
        $features | Out-String | Set-Content -Path $featuresFile
        Write-Host "Installed features documented successfully." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to document installed features: $($_.Exception.Message)" -ForegroundColor $WarningColor
    }

    # Export security configuration
    $seceditFile = Join-Path -Path $docsFolder -ChildPath "secedit-export.inf"
    Write-Host "Exporting security configuration to: $seceditFile" -ForegroundColor $PromptColor
    try {
        secedit /export /cfg "$seceditFile" | Out-Null
        Write-Host "Security configuration exported successfully." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to export security configuration: $($_.Exception.Message)" -ForegroundColor $WarningColor
    }

    # Document Windows Defender preferences
    $defenderFile = Join-Path -Path $docsFolder -ChildPath "defender.txt"
    Write-Host "Documenting Windows Defender preferences to: $defenderFile" -ForegroundColor $PromptColor
    try {
        Get-MpPreference | Out-String | Set-Content -Path $defenderFile
        Write-Host "Windows Defender preferences documented successfully." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to document Windows Defender preferences: $($_.Exception.Message)" -ForegroundColor $WarningColor
    }

    # Document scheduled tasks
    $tasksFile = Join-Path -Path $docsFolder -ChildPath "tasks.txt"
    Write-Host "Documenting scheduled tasks to: $tasksFile" -ForegroundColor $PromptColor
    try {
        Get-ScheduledTask | Select-Object TaskName, State | Format-Table -AutoSize | Out-String | Set-Content -Path $tasksFile
        Write-Host "Scheduled tasks documented successfully." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to document scheduled tasks: $($_.Exception.Message)" -ForegroundColor $WarningColor
    }

    Write-Host "Documentation process completed." -ForegroundColor $HeaderColor
}


function Enable-Updates {
    Write-Host "`n--- Starting: Enable Updates ---`n" -ForegroundColor $HeaderColor

    # Check if PSWindowsUpdate module is available
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Host "The 'PSWindowsUpdate' module is not installed. Installing now..." -ForegroundColor $PromptColor
        try {
            Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop
            Write-Host "'PSWindowsUpdate' module installed successfully." -ForegroundColor $EmphasizedNameColor
        } catch {
            Write-Host "Failed to install PSWindowsUpdate module: $($_.Exception.Message)" -ForegroundColor $WarningColor
            return
        }
    }

    Import-Module PSWindowsUpdate

    # Search for available updates
    Write-Host "Searching for available updates..." -ForegroundColor $PromptColor
    try {
        $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
    } catch {
        Write-Host "Error checking for updates: $($_.Exception.Message)" -ForegroundColor $WarningColor
        return
    }

    if (-not $updates) {
        Write-Host "No updates available." -ForegroundColor $EmphasizedNameColor
        return
    }

    Write-Host "`nFound $($updates.Count) update(s)." -ForegroundColor $EmphasizedNameColor

    # Loop through each update and ask before installing
    foreach ($update in $updates) {
        Write-Host "`nUpdate: $($update.Title)" -ForegroundColor $PromptColor
        $answer = Read-Host "Do you want to install this update? [Y/n] (default Y)"

        if ($answer -eq 'n' -or $answer -eq 'N') {
            Write-Host "Skipped: $($update.Title)" -ForegroundColor $RemovedLineColor
            continue
        }

        try {
            Write-Host "Installing update: $($update.Title)" -ForegroundColor $EmphasizedNameColor
            Install-WindowsUpdate -Title $update.Title -AcceptAll -IgnoreReboot -ErrorAction Stop
            Write-Host "Successfully installed: $($update.Title)" -ForegroundColor $KeptLineColor
        } catch {
            Write-Host "Failed to install $($update.Title): $($_.Exception.Message)" -ForegroundColor $WarningColor
        }
    }

    Write-Host "`nUpdate process completed." -ForegroundColor $HeaderColor
}

function User-Auditing {
    Write-Host "`n--- Starting: User Auditing ---`n" -ForegroundColor $HeaderColor

    # Disable and rename the built-in Guest account
    Write-Host "Checking for the built-in Guest account..." -ForegroundColor $PromptColor
    try {
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction Stop
        Write-Host "Disabling and renaming the built-in Guest account..." -ForegroundColor $PromptColor
        Disable-LocalUser -Name "Guest"
        Write-Host "Guest account has been disabled." -ForegroundColor $EmphasizedNameColor

        Rename-LocalUser -Name "Guest" -NewName "DisabledGuest"
        Write-Host "Guest account has been renamed to 'DisabledGuest'." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Guest account not found or already renamed." -ForegroundColor $WarningColor
    }

    # Disable and rename the built-in Administrator account
    Write-Host "Checking for the built-in Administrator account..." -ForegroundColor $PromptColor
    try {
        Get-LocalUser -Name "Administrator" -ErrorAction Stop
        Write-Host "Disabling and renaming the built-in Administrator account..." -ForegroundColor $PromptColor
        Disable-LocalUser -Name "Administrator"
        Write-Host "Administrator account has been disabled." -ForegroundColor $EmphasizedNameColor

        Rename-LocalUser -Name "Administrator" -NewName "SecAdminDisabled"
        Write-Host "Administrator account has been renamed to 'SecAdminDisabled'." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Administrator account not found or already renamed." -ForegroundColor $WarningColor
    }

    # Enumerate all local user accounts
    $localUsers = Get-LocalUser

    foreach ($user in $localUsers) {
        # Skip built-in accounts
        if ($user.Name -in @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')) {
            continue
        }

        #Write-Host "Is '$($user.Name)' an Authorized User? [Y/n]:" -ForegroundColor $PromptColor
        # Inline colored prompt using multiple segments (PS 5.1-safe)
        Write-Host -NoNewline "Is " -ForegroundColor $EmphasizedNameColor
        Write-Host -NoNewline "$($user.Name)" -ForegroundColor $PromptColor
        Write-Host -NoNewline " an Authorized User? [Y/n] (default Y) " -ForegroundColor $EmphasizedNameColor

        $answer = Read-Host
        try {
            # Set password to $TempPassword
            Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $TempPassword -AsPlainText -Force)
            Write-Host "Password for '$($user.Name)' reset to temporary value." -ForegroundColor $EmphasizedNameColor

            # Require password change at next logon
            net user $user.Name /logonpasswordchg:yes
            Write-Host "User '$($user.Name)' must change password at next logon." -ForegroundColor $EmphasizedNameColor
        } catch {
            Write-Host "Failed to reset password for '$($user.Name)': $_" -ForegroundColor $WarningColor
        }

        if ($answer -eq 'n' -or $answer -eq 'N') {
            try {
                Remove-LocalUser -Name $user.Name
                Write-Host "Deleted user: $($user.Name)" -ForegroundColor $RemovedLineColor
            } catch {
                Write-Host "Failed to delete user: $($user.Name) - $_" -ForegroundColor $WarningColor
            }
        } else {
            Write-Host "Kept user: $($user.Name)" -ForegroundColor $KeptLineColor
        }
    }

    # After all users have been processed, enumerate all users in the Administrators group
    $adminGroup = Get-LocalGroupMember -Group "Administrators"

    foreach ($admin in $adminGroup) {
        # Only process user accounts (not groups or service accounts) 
        if ($admin.ObjectClass -ne 'User') {
            continue
        }

        Write-Host "Is '$($admin.Name)' an Authorized Administrator? [Y/n]:" -ForegroundColor $PromptColor
        $answer = Read-Host

        if ($answer -eq 'n' -or $answer -eq 'N') {
            try {
                Remove-LocalGroupMember -Group "Administrators" -Member $admin.Name
                Write-Host "Removed administrator: $($admin.Name)" -ForegroundColor $RemovedLineColor
            } catch {
                Write-Host "Failed to remove administrator: $($admin.Name) - $_" -ForegroundColor $WarningColor
            }
        } else {
            Write-Host "Kept administrator: $($admin.Name)" -ForegroundColor $KeptLineColor
        }
    }
    # === Prompt to add new users ===
do {
    Write-Host "`nWould you like to add a new user? [Y/n] (default N)" -ForegroundColor $PromptColor
    $addUserAnswer = Read-Host

    if ($addUserAnswer -eq 'y' -or $addUserAnswer -eq 'Y') {
        $newUsername = Read-Host "Enter the new username"
        $newFullName = Read-Host "Enter the user's full name (can be blank)"

        try {
            # Create new local user
            $securePassword = ConvertTo-SecureString $TempPassword -AsPlainText -Force
            New-LocalUser -Name $newUsername -Password $securePassword -FullName $newFullName -UserMayNotChangePassword $false -PasswordNeverExpires $false
            Write-Host "User '$newUsername' created successfully with temporary password." -ForegroundColor $EmphasizedNameColor

            # Force password change at next login
            net user $newUsername /logonpasswordchg:yes
            Write-Host "User '$newUsername' must change password at next logon." -ForegroundColor $KeptLineColor

            # Ask to add to Administrators group
            $adminAnswer = Read-Host "Add '$newUsername' to Administrators group? [y/N]"
            if ($adminAnswer -eq 'y' -or $adminAnswer -eq 'Y') {
                Add-LocalGroupMember -Group "Administrators" -Member $newUsername
                Write-Host "User '$newUsername' added to Administrators group." -ForegroundColor $KeptLineColor
            } else {
                Write-Host "User '$newUsername' was not added to Administrators group." -ForegroundColor $KeptLineColor
            }
        } catch {
            Write-Host "Failed to create user: $($_.Exception.Message)" -ForegroundColor $WarningColor
        }
    }
} while ($addUserAnswer -eq 'y' -or $addUserAnswer -eq 'Y')

    Write-Host "`nUser auditing process completed." -ForegroundColor $HeaderColor
}

function Account-Policies {
    Write-Host "`n--- Starting: Account Policies ---`n"
    Write-Host "Setting maximum password age to $MaxPasswordAge days..." #1CyberPatriot!
    net accounts /maxpwage:$MaxPasswordAge
    Write-Host "`n--- Starting: Setting Account Policies ---`n" -ForegroundColor Cyan

    # Set the maximum password age using the net accounts command
    try {
        Write-Host "Setting Maximum Password Age to $MaxPasswordAge days..." -ForegroundColor Yellow
        net accounts /MAXPWAGE:$MaxPasswordAge | Out-Null
        Write-Host "Successfully set Maximum Password Age to $MaxPasswordAge days." -ForegroundColor Green
    } catch {
        Write-Host "Failed to export security policy: $($_.Exception.Message)" -ForegroundColor $WarningColor
        return
    }
}
function Local-Policies {}
    Write-Host "`n--- Starting: Local-Policies ---`n"
    # Define paths for security config files
$exportedFile = "C:\Windows\Security\Temp\secpol_original.inf"
$modifiedFile = "C:\Windows\Security\Temp\secpol_modified.inf"

# Create the temp folder if it doesn't exist
if (-not (Test-Path "C:\Windows\Security\Temp")) {
    New-Item -Path "C:\Windows\Security\Temp" -ItemType Directory | Out-Null
}

# Export current security policy to the file
Write-Host "Exporting current security policy to: $exportedFile" -ForegroundColor $PromptColor
try {
    secedit /export /cfg $exportedFile | Out-Null
    Write-Host "Security policy exported successfully." -ForegroundColor $EmphasizedNameColor
} catch {
    Write-Host "Failed to export security policy: $($_.Exception.Message)" -ForegroundColor $WarningColor
    return
}

    # Modify the security privileges
    function Local-Policies {
    Write-Host "`n--- Starting: Local-Policies ---`n"

    # Paths for exported and modified security templates
    $exportedFile = "C:\Windows\Security\Temp\secpol_export.inf"
    $modifiedFile = "C:\Windows\Security\Temp\secpol_modified.inf"

    # Make sure the folder exists
    if (-not (Test-Path "C:\Windows\Security\Temp")) {
        New-Item -Path "C:\Windows\Security\Temp" -ItemType Directory -Force | Out-Null
    }

    # Export the current security policy
    Write-Host "Exporting current security policy..." -ForegroundColor $HeaderColor
    secedit /export /cfg $exportedFile /quiet

    Write-Host "Modifying security privileges..." -ForegroundColor $HeaderColor
    try {
        (Get-Content $exportedFile) `
            -replace '\(SeTrustedCredManAccessPrivilege.*$', 'SeTrustedCredManAccessPrivilege = *S-1-5-32-544' `
            -replace '\(SeDenyNetworkLogonRight.*$', 'SeDenyNetworkLogonRight = *S-1-1-0,*S-1-5-32-546' `
            -replace '\(SeCreateTokenPrivilege.*$', 'SeCreateTokenPrivilege = *S-1-5-32-544' `
            -replace '\(SeCreateGlobalPrivilege.*$', 'SeCreateGlobalPrivilege = *S-1-5-32-544' `
            -replace '\(SeRemoteShutdownPrivilege.*$', 'SeRemoteShutdownPrivilege = *S-1-5-32-544' `
            -replace '\(SeLoadDriverPrivilege.*$', 'SeLoadDriverPrivilege = *S-1-5-32-544' `
            -replace '\(SeSecurityPrivilege.*$', 'SeSecurityPrivilege = *S-1-5-32-544' `
            | Set-Content $modifiedFile
        Write-Host "Security privileges modified successfully." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to modify security privileges: $($_.Exception.Message)" -ForegroundColor $WarningColor
        return
    }
$seceditDBPath = "C:\Windows\Security\Database\secedit.sdb"

Write-Host "Importing modified security policy..." -ForegroundColor $HeaderColor

secedit /configure /db "C:\Windows\Security\Database\custom.sdb" /cfg "C:\Windows\Security\Temp\secpol_modified.inf" /overwrite /log "C:\Windows\Security\Logs\secedit.log" /quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "Security policy updated successfully." -ForegroundColor $EmphasizedNameColor
} else {
    Write-Host "Failed to import modified security policy." -ForegroundColor $WarningColor
    Write-Host "Error Output:`n$seceditOutput" -ForegroundColor $WarningColor
}
}
function Defensive-Countermeasures {
    Write-Host "`n--- Starting: Defensive Countermeasures ---`n"
}

function Uncategorized-OS-Settings {
    Write-Host "`n--- Starting: Uncategorized OS Settings ---`n"
}

function Service-Auditing {
    Write-Host "`n--- Starting: Service Auditing ---`n"

    # Define the services to audit and disabled
    $servicesToAudit = @( "BTAGService", "bthserv", "Browser", "MapsBroker", "lfsvc", "IISADMIN", "irmon", "lltdsvc", 
    "LxssManager", "FTPSVC", "MSiSCSI", "sshd", "PNRPsvc", "p2psvc", "p2pimsvc", "PNRPAutoReg", 
    "Spooler", "wercplsupport", "RasAuto", "SessionEnv", "TermService", "UmRdpService", "RpcLocator", 
    "RemoteRegistry", "RemoteAccess", "LanmanServer", "simptcp", "SNMP", "sacsvr", "SSDPSRV", 
    "upnphost", "WMSvc", "WerSvc", "Wecsvc", "WMPNetworkSvc", "icssvc", "WpnService", "PushToInstall", 
    "WinRM", "W3SVC", "XboxGipSvc", "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "NetTcpPortSharing",
    "DNS", "LPDsvc", "RasMan", "SNMPTRAP", "TlntSvr", "TapiSrv", "WebClient", "LanmanWorkstation")

    # Display the current status of the services
    Write-Host "`nCurrent status of services:`n"
    Get-Service -Name $servicesToAudit -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-Table -AutoSize

    # Loop through each service and attempt to disable it
    foreach ($service in $servicesToAudit) {
        try {
            $svc = Get-Service -Name $service -ErrorAction Stop
            if ($svc.Status -ne "Stopped") {
                Stop-Service -Name $service -Force -ErrorAction Stop
                Write-Host "Stopped service: $service"
            }
            Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
            Write-Host "Disabled service: $service"
        } catch {
            Write-Warning "Could not modify $service`: $($_.Exception.Message)"
        }
    }
    
    # Display the updated status of the services
    Write-Host "`nUpdated status of services:`n"
    Get-Service -Name $servicesToAudit -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-Table -AutoSize
}

function OS-Updates {
    Write-Host "`n--- Starting: OS Updates ---`n" -ForegroundColor $HeaderColor

    # Re-enable Windows Update service
    try {
        Write-Host "Re-enabling Windows Update service (wuauserv)..." -ForegroundColor $PromptColor
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction Stop
        Write-Host "Windows Update service is enabled and running." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "Failed to enable Windows Update service: $($_.Exception.Message)" -ForegroundColor $WarningColor
        return
    }

    # Create DOCS folder for logging
    $desktopFolder = [Environment]::GetFolderPath("Desktop")
    $docsFolder = Join-Path $desktopFolder "DOCS"
    if (-not (Test-Path $docsFolder)) {
        New-Item -Path $docsFolder -ItemType Directory -Force | Out-Null
    }
    $updatesFile = Join-Path $docsFolder "AvailableUpdates.txt"

    # Try PSWindowsUpdate module first (non-blocking audit only)
    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
        try {
            Write-Host "Checking for updates using PSWindowsUpdate..." -ForegroundColor $PromptColor
            $updates = Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -ErrorAction Stop
            if ($updates -and $updates.Count -gt 0) {
                $updates | Select-Object KB, Title, Size, IsDownloaded, IsInstalled |
                    Format-Table -AutoSize | Out-String | Set-Content $updatesFile
                Write-Host "Updates documented at: $updatesFile" -ForegroundColor $PromptColor
            } else {
                Write-Host "No updates found via PSWindowsUpdate." -ForegroundColor $EmphasizedNameColor
            }
        } catch {
            Write-Host "PSWindowsUpdate check failed: $($_.Exception.Message)" -ForegroundColor $WarningColor
        }
    } else {
        Write-Host "PSWindowsUpdate not installed — skipping audit." -ForegroundColor $WarningColor
    }

    # Always trigger background install with UsoClient (non-blocking)
    Write-Host "Triggering updates via UsoClient..." -ForegroundColor $PromptColor
    try {
        UsoClient StartScan
        UsoClient StartDownload
        UsoClient StartInstall
        Write-Host "Updates triggered. Windows may reboot automatically if needed." -ForegroundColor $EmphasizedNameColor
    } catch {
        Write-Host "UsoClient failed: $($_.Exception.Message)" -ForegroundColor $WarningColor
    }

    Write-Host "`n--- OS Updates process completed ---`n" -ForegroundColor $HeaderColor
}
 
}

function Application-Updates {
    Write-Host "`n--- Starting: Application Updates ---`n"
}

function Prohibited-Files {
    Write-Host "`n--- Starting: Prohibited Files ---`n"
}

function Unwanted-Software {
    Write-Host "`n--- Starting: Unwanted Software ---`n"
}

function Malware {
    Write-Host "`n--- Starting: Malware ---`n"
}
#local policies
function Application-Security-Settings {
    Write-Host "`n--- Starting: Application Security Settings ---`n"
}

# Define a list to track completed options
$completedOptions = @()

# Menu loop
do {
    Write-Host "`nSelect an option:`n"
    for ($i = 0; $i -lt $menuOptions.Count; $i++) {
        if ($completedOptions -contains $menuOptions[$i]) {
            # Highlight completed options in green
            Write-Host "$($i + 1). $($menuOptions[$i])" -ForegroundColor $EmphasizedNameColor
        } else {
            # Display incomplete options in default color
            Write-Host "$($i + 1). $($menuOptions[$i])"
        }
    }

    $selection = Read-Host "`nEnter the number of your choice"

    switch ($selection) {
        "1"  { 
            Document-System 
            $completedOptions += $menuOptions[0]  # Mark as completed
        }
        "2"  { 
            Enable-Updates 
            $completedOptions += $menuOptions[1]  # Mark as completed
        }
        "3"  { 
            User-Auditing 
            $completedOptions += $menuOptions[2]  # Mark as completed
        }
        "4"  { 
            Account-Policies 
            $completedOptions += $menuOptions[3]  # Mark as completed
        }
        "5"  { 
            Local-Policies 
            $completedOptions += $menuOptions[4]  # Mark as completed
        }
        "6"  { 
            Defensive-Countermeasures 
            $completedOptions += $menuOptions[5]  # Mark as completed
        }
        "7"  { 
            Uncategorized-OS-Settings 
            $completedOptions += $menuOptions[6]  # Mark as completed
        }
        "8"  { 
            Service-Auditing 
            $completedOptions += $menuOptions[7]  # Mark as completed
        }
        "9"  { 
            OS-Updates 
            $completedOptions += $menuOptions[8]  # Mark as completed
        }
        "10" { 
            Application-Updates 
            $completedOptions += $menuOptions[9]  # Mark as completed
        }
        "11" { 
            Prohibited-Files 
            $completedOptions += $menuOptions[10]  # Mark as completed
        }
        "12" { 
            Unwanted-Software 
            $completedOptions += $menuOptions[11]  # Mark as completed
        }
        "13" { 
            Malware 
            $completedOptions += $menuOptions[12]  # Mark as completed
        }
        "14" { 
            Application-Security-Settings 
            $completedOptions += $menuOptions[13]  # Mark as completed
        }
        "15" { 
            Write-Host "`nExiting..." 
            break menu  # Exit the loop
        }
        default { 
            Write-Host "`nInvalid selection. Please try again." -ForegroundColor $WarningColor
        }
    }
} while ($true)
# End of script 
#Changed
#Chnanged again
#change
#merge

