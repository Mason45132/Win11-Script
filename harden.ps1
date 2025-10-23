# ===== Variables Section Start =====
$MaxPasswordAge = 60  # Maximum password age in days
$MinPasswordAge = 10   # Minimum password age in days
$TempPassword = '1P@ssword!' # Temporary password for user accounts
$MinPasswordLength = 10  # Minimum password length
$LockoutThreshold = 5  # Account lockout threshold
$LockoutDuration = 30  # Account lockout duration in minutes
$LockoutWindow = 30    # Account lockout observation window in minutes
$passwordhistorySize = 24 # Number of previous passwords to remember
# Color variables ====
$HeaderColor = "Cyan"            # Color for headers
$PromptColor = "Yellow"          # Color for prompts
$EmphasizedNameColor = "Green"   # Color for emphasized names
$KeptLineColor = "DarkYellow"    # Color for kept lines
$RemovedLineColor = "Red"        # Color for removed lines
$WarningColor = "Red"            # Color for warnings
# ===== Variables Section End =====

# Check for admin rights and relaunch as admin if needed                       TempPassword = '?1CyberPatriot!?'
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

    $rebootRequired = $false

    # Ensure TLS 1.2 is enabled for secure downloads (only once per session)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Check if PSWindowsUpdate module is available, install if not
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    
        Write-Host "The 'PSWindowsUpdate' module is not installed. Installing now..." -ForegroundColor $PromptColor
        try {
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
            }
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop
            Write-Host "'PSWindowsUpdate' module installed successfully." -ForegroundColor $EmphasizedNameColor
        } catch {
            Write-Host "Failed to install PSWindowsUpdate module: $($_.Exception.Message)" -ForegroundColor $WarningColor
            return
        }
    }

    Import-Module PSWindowsUpdate

    # Search for available updates
    # ERROR: try  --Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned--
    Write-Host "Searching for available updates..." -ForegroundColor $PromptColor
    try {
        $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
    } catch {
        Write-Host "Error checking for updates: $($_.Exception.Message)" -ForegroundColor $WarningColor
        return
    }

    if (-not $updates) {
        Write-Host "No updates available." -ForegroundColor $EmphasizedNameColor
    } else {
        Write-Host "`nFound $($updates.Count) update(s)." -ForegroundColor $EmphasizedNameColor

        foreach ($update in $updates) {
            Write-Host "`nUpdate: $($update.Title)" -ForegroundColor $PromptColor
            $answer = Read-Host "Do you want to install this update? [Y/n] (default Y)"

            if ($answer -eq 'n' -or $answer -eq 'N') {
                Write-Host "Skipped: $($update.Title)" -ForegroundColor $RemovedLineColor
                continue
            }

            try {
                Write-Host "Installing update: $($update.Title)" -ForegroundColor $EmphasizedNameColor

                if ($update.KBArticleIDs -and $update.KBArticleIDs.Count -gt 0) {
                    Install-WindowsUpdate -KBArticleID $update.KBArticleIDs[0] -AcceptAll -IgnoreReboot -ErrorAction Stop
                } elseif ($update.UpdateID) {
                    Install-WindowsUpdate -UpdateID $update.UpdateID -AcceptAll -IgnoreReboot -ErrorAction Stop
                } else {
                    Install-WindowsUpdate -Title $update.Title -AcceptAll -IgnoreReboot -ErrorAction Stop
                }

                Write-Host "Successfully installed: $($update.Title)" -ForegroundColor $KeptLineColor

                # Check if reboot is required
                if ((Get-WURebootStatus).RebootRequired) {
                    $rebootRequired = $true
                }

            } catch {
                Write-Host "Failed to install $($update.Title): $($_.Exception.Message)" -ForegroundColor $WarningColor
            }
        }
    }

    # --- Chrome Installation/Update Check ---
    Write-Host "`n--- Checking Google Chrome ---" -ForegroundColor $HeaderColor

    $chromePaths = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe"
    )
    $chromeInstalled = $chromePaths | Where-Object { Test-Path $_ }

    if (-not $chromeInstalled) {
        Write-Host "Google Chrome is not installed. Installing now..." -ForegroundColor $PromptColor
        $chromeInstallerUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
        $tempInstaller = "$env:TEMP\chrome_installer.exe"

        try {
            Invoke-WebRequest -Uri $chromeInstallerUrl -OutFile $tempInstaller -ErrorAction Stop
            Start-Process -FilePath $tempInstaller -Args "/silent /install" -Wait
            Write-Host "Google Chrome has been installed." -ForegroundColor $KeptLineColor
        } catch {
            Write-Host "Failed to install Chrome: $($_.Exception.Message)" -ForegroundColor $WarningColor
        } finally {
            if (Test-Path $tempInstaller) { Remove-Item $tempInstaller -Force }
        }
    } else {
        Write-Host "Google Chrome is already installed. Checking for updates..." -ForegroundColor $PromptColor

        $chromeUpdater = "$env:ProgramFiles\Google\Update\GoogleUpdate.exe"
        if (-not (Test-Path $chromeUpdater)) {
            $chromeUpdater = "$env:ProgramFiles(x86)\Google\Update\GoogleUpdate.exe"
        }

        if (Test-Path $chromeUpdater) {
            try {
                Start-Process -FilePath $chromeUpdater -ArgumentList "/ua /installsource scheduler" -Wait
                Write-Host "Chrome update process triggered." -ForegroundColor $KeptLineColor
            } catch {
                Write-Host "Failed to run Chrome updater: $($_.Exception.Message)" -ForegroundColor $WarningColor
            }
        } else {
            Write-Host "Chrome updater not found. Reinstalling Chrome to restore update functionality..." -ForegroundColor $WarningColor

            $chromeInstallerUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
            $tempInstaller = "$env:TEMP\chrome_installer.exe"

            try {
                Invoke-WebRequest -Uri $chromeInstallerUrl -OutFile $tempInstaller -ErrorAction Stop
                Start-Process -FilePath $tempInstaller -Args "/silent /install" -Wait
                Write-Host "Chrome reinstalled successfully. Updater should now be restored." -ForegroundColor $KeptLineColor
            } catch {
                Write-Host "Failed to reinstall Chrome: $($_.Exception.Message)" -ForegroundColor $WarningColor
            } finally {
                if (Test-Path $tempInstaller) { Remove-Item $tempInstaller -Force }
            }
        }
    }

    # --- Firefox Installation/Update Check ---
    Write-Host "`n--- Checking Firefox ---" -ForegroundColor $HeaderColor

    $firefoxPath = "C:\Program Files\Mozilla Firefox\firefox.exe"
    if (Test-Path $firefoxPath) {
        $firefoxVersion = (Get-Item $firefoxPath).VersionInfo.ProductVersion
        Write-Host "Firefox is installed. Version: $firefoxVersion" -ForegroundColor Green
    } else {
        Write-Host "Firefox is not installed. Skipping update check." -ForegroundColor Yellow
    }

    # --- CCleaner Installation/Update Check ---
    Write-Host "`n--- Checking CCleaner ---" -ForegroundColor $HeaderColor

    $ccleanerPath = "C:\Program Files\CCleaner\CCleaner.exe"
    if (Test-Path $ccleanerPath) {
        $ccleanerVersion = (Get-Item $ccleanerPath).VersionInfo.ProductVersion
        Write-Host "CCleaner is installed. Version: $ccleanerVersion" -ForegroundColor Green
    } else {
        Write-Host "CCleaner is not installed. Skipping update check." -ForegroundColor Yellow
    }

    # Prompt for reboot if needed
    if ($rebootRequired) {
        Write-Host "`nOne or more updates require a system restart." -ForegroundColor $WarningColor
        $rebootAnswer = Read-Host "Do you want to reboot now? [Y/n] (default Y)"
        if ($rebootAnswer -eq 'n' -or $rebootAnswer -eq 'N') {
            Write-Host "System reboot skipped. Please remember to restart manually." -ForegroundColor $PromptColor
        } else {
            Write-Host "Rebooting system now..." -ForegroundColor $HeaderColor
            Restart-Computer -Force
        }
    }

    Write-Host "`n--- Enable Updates process completed ---`n" -ForegroundColor $HeaderColor
}

function AuditUsers {
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
            try {
                Unlock-LocalUser -Name $user.Name
                Write-Host "Unlocked user: $($user.Name)" -ForegroundColor $KeptLineColor
            } catch {
                Write-Host "Kept user: $($user.Name) (could not unlock or already unlocked)" -ForegroundColor $KeptLineColor
            }
        }
    }

    # After all users have been processed, enumerate all users in the Administrators group
    $adminGroup = Get-LocalGroupMember -Group "Administrators"
    foreach ($admin in $adminGroup) {
        # Only process user accounts (not groups or service accounts) 
        if ($admin.ObjectClass -ne 'User') { continue }
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
                New-LocalUser -Name $newUsername -Password $securePassword -FullName $newFullName
                # Apply additional settings after user creation
                net user $newUsername /passwordchg:yes
                net user $newUsername /expires:never
                Write-Host "User '$newUsername' created successfully with temporary password." -ForegroundColor $EmphasizedNameColor
                # Force password change at next login
                net user $newUsername /logonpasswordchg:yes
                # Ask to add to Administrators group
                $adminAnswer = Read-Host "Add '$newUsername' to Administrators group? [y/N]"
                if ($adminAnswer -eq 'y' -or $adminAnswer -eq 'Y') {
                    Add-LocalGroupMember -Group "Administrators" -Member $newUsername
                    Write-Host "User '$newAdminUsername' added to Administrators group." -ForegroundColor $KeptLineColor
                } else {
                    Write-Host "User '$newAdminUsername' was not added to Administrators group." -ForegroundColor $KeptLineColor
                }
            } catch {
                Write-Host "Failed to create user: $($_.Exception.Message)" -ForegroundColor $WarningColor
            }
        }
    } while ($addUserAnswer -eq 'y' -or $addUserAnswer -eq 'Y')

    # === Prompt to add a new Administrator account separately ===
    Write-Host "`nWould you like to add a new Administrator account? [Y/n] (default N)" -ForegroundColor $PromptColor
    $addAdminAnswer = Read-Host
    if ($addAdminAnswer -eq 'y' -or $addAdminAnswer -eq 'Y') {
        $newAdminUsername = Read-Host "Enter the new administrator username"
        $newAdminFullName = Read-Host "Enter the full name (can be blank)"
        try {
            $securePassword = ConvertTo-SecureString $TempPassword -AsPlainText -Force
            New-LocalUser -Name $newAdminUsername -Password $securePassword -FullName $newAdminFullName
            # Apply additional settings after admin creation
            net user $newAdminUsername /passwordchg:yes
            net user $newAdminUsername /expires:never
            Write-Host "Administrator account '$newAdminUsername' created successfully." -ForegroundColor $EmphasizedNameColor
            net user $newAdminUsername /logonpasswordchg:yes
            Add-LocalGroupMember -Group "Administrators" -Member $newAdminUsername
            Write-Host "User '$newAdminUsername' added to Administrators group and must change password at next login." -ForegroundColor $KeptLineColor
        } catch {
            Write-Host "Failed to create administrator account: $($_.Exception.Message)" -ForegroundColor $WarningColor
        }
    }

    #===== Add Group =====
    Write-Host "`nWould you like to add a new group? [Y/n] (default N)" -ForegroundColor $PromptColor
    $addGroupAnswer = Read-Host
    if ($addGroupAnswer -eq 'y' -or $addGroupAnswer -eq 'Y') {
        $newGroupName = Read-Host "Enter the new group name"
        try {
            New-LocalGroup -Name $newGroupName
            Write-Host "Group '$newGroupName' created successfully." -ForegroundColor $EmphasizedNameColor
            $addMembersAnswer = Read-Host "Would you like to add members to '$newGroupName'? [Y/n] (default N)"
            if ($addMembersAnswer -eq 'y' -or $addMembersAnswer -eq 'Y') {
                do {
                    $memberName = Read-Host "Enter the username to add to '$newGroupName'"
                    try {
                        Add-LocalGroupMember -Group $newGroupName -Member $memberName
                        Write-Host "User '$memberName' added to group '$newGroupName'." -ForegroundColor $KeptLineColor
                    } catch {
                        Write-Host "Failed to add user to group: $($_.Exception.Message)" -ForegroundColor $WarningColor
                    }
                    $moreMembers = Read-Host "Add another member? [Y/n] (default N)"
                } while ($moreMembers -eq 'y' -or $moreMembers -eq 'Y')
            }
        } catch {
            Write-Host "Failed to create group: $($_.Exception.Message)" -ForegroundColor $WarningColor
        }
    } else {
        Write-Host "No new group created." -ForegroundColor $KeptLineColor
    }
    Write-Host "Would you like to delete an existing group? [Y/n] (default N)" -ForegroundColor $PromptColor
    $deleteGroupAnswer = Read-Host
    if ($deleteGroupAnswer -eq 'y' -or $deleteGroupAnswer -eq 'Y') {
        do {
            $groupNameToDelete = Read-Host "Enter the group name to delete"
            try {
                Remove-LocalGroup -Name $groupNameToDelete
                Write-Host "Group '$groupNameToDelete' deleted successfully." -ForegroundColor $EmphasizedNameColor
            } catch {
                Write-Host "Failed to delete group: $($_.Exception.Message)" -ForegroundColor $WarningColor
            }
            $moreGroupsToDelete = Read-Host "Delete another group? [Y/n] (default N)"
        } while ($moreGroupsToDelete -eq 'y' -or $moreGroupsToDelete -eq 'Y')
    } else {
        Write-Host "No groups deleted." -ForegroundColor $KeptLineColor
    }
    Write-Host "`nUser auditing process completed." -ForegroundColor $HeaderColor
}

function Account-Policies {
    Write-Host "`n--- Starting: Account Policies ---`n"

    # Set the maximum password age
    Write-Host "Setting maximum password age to $MaxPasswordAge days..." -ForegroundColor Yellow
    try {
        net accounts /MAXPWAGE:$MaxPasswordAge | Out-Null
        Write-Host "Successfully set Maximum Password Age to $MaxPasswordAge days." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set Maximum Password Age: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Set the minimum password length
    Write-Host "Setting minimum password length to $MinPasswordLength characters..." -ForegroundColor Yellow
    try {
        net accounts /MINPWLEN:$MinPasswordLength | Out-Null
        Write-Host "Successfully set Minimum Password Length to $MinPasswordLength characters." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set Minimum Password Length: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Set the minimum password age
    Write-Host "Setting minimum password age to $MinPasswordAge day..." -ForegroundColor Yellow
    try {
        net accounts /MINPWAGE:$MinPasswordAge | Out-Null
        Write-Host "Successfully set Minimum Password Age to $MinPasswordAge day." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set Minimum Password Age: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Set password history
    Write-Host "Enforcing password history to remember last 24 passwords..." -ForegroundColor Yellow
    try {
    
        secedit /export /cfg temp.inf
        (Get-Content temp.inf).replace("$passwordhistorySize = 0", "$passwordhistorySize = 24") | Set-Content temp_modified.inf
        secedit /configure /db secedit.sdb /cfg temp_modified.inf /areas SECURITYPOLICY | Out-Null
        Remove-Item temp.inf, temp_modified.inf -Force
        Write-Host "Password history policy set successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set password history: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Enforce password complexity
    Write-Host "Enforcing password complexity requirements..." -ForegroundColor Yellow
    try {
        secedit /export /cfg temp.inf
        (Get-Content temp.inf).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Set-Content temp_modified.inf
        secedit /configure /db secedit.sdb /cfg temp_modified.inf /areas SECURITYPOLICY | Out-Null
        Remove-Item temp.inf, temp_modified.inf -Force
        Write-Host "Password complexity enforced successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to enforce password complexity: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Disable reversible encryption
    Write-Host "Disabling reversible encryption for passwords..." -ForegroundColor Yellow
    try {
        reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "StoreClearText" /t REG_DWORD /d 0 /f | Out-Null
        Write-Host "Reversible encryption disabled successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable reversible encryption: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Set account lockout threshold
    Write-Host "Setting account lockout threshold to 5 attempts..." -ForegroundColor Yellow
    try {
        net accounts /LOCKOUTTHRESHOLD:$LockoutThreshold | Out-Null
        Write-Host "Successfully set Account Lockout Threshold to $LockoutThreshold attempts." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set Account Lockout Threshold: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Set lockout observation window
    Write-Host "Setting account lockout observation window to $LockoutWindow minutes..." -ForegroundColor Yellow
    try {
        net accounts /LOCKOUTWINDOW:$LockoutWindow | Out-Null
        Write-Host "Successfully set Account Lockout Observation Window to $LockoutWindow minutes." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set Account Lockout Observation Window: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Set account lockout duration
    Write-Host "Setting account lockout duration to $LockoutDuration minutes..." -ForegroundColor Yellow
    try {
        net accounts /LOCKOUTDURATION:$LockoutDuration | Out-Null
        Write-Host "Successfully set Account Lockout Duration to $LockoutDuration minutes." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set Account Lockout Duration: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    Write-Host "`n--- Finished: Setting Account Policies ---`n" -ForegroundColor Cyan
}

function Local-Policies {
    Write-Host "`n--- Applying Local Policies ---`n" -ForegroundColor Cyan

    # Enable Audit Logon [Success]
    Write-Host "Enabling Audit Logon [Success]..." -ForegroundColor Cyan
    auditpol /set /subcategory:"Logon" /success:enable
    Write-Host "Audit Logon [Success] enabled." -ForegroundColor Green

    # Enable Audit Logoff [Failure]
    Write-Host "Enabling Audit Logoff [Failure]..." -ForegroundColor Cyan
    auditpol /set /subcategory:"Logoff" /failure:enable
    Write-Host "Audit Logoff [Failure] enabled." -ForegroundColor Green

    # Restrict network access for Everyone group
    Write-Host "Restricting network access for Everyone group..." -ForegroundColor Cyan
    secedit /export /cfg $env:TEMP\secpol.inf
    (Get-Content $env:TEMP\secpol.inf).replace("SeNetworkLogonRight = *S-1-1-0", "SeNetworkLogonRight =") | Set-Content $env:TEMP\secpol_modified.inf
    secedit /configure /db secedit.sdb /cfg $env:TEMP\secpol_modified.inf /areas USER_RIGHTS
    Write-Host "Network access restricted for Everyone group." -ForegroundColor Green

    # Prevent users from installing printer drivers
    Write-Host "Preventing users from installing printer drivers..." -ForegroundColor Cyan
    reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "PointAndPrintRestrictions" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "NoWarningNoElevationOnInstall" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "UpdatePromptSettings" /t REG_DWORD /d 2 /f | Out-Null
    Write-Host "Users are now prevented from installing printer drivers." -ForegroundColor Green

    # Enforce CTRL+ALT+DEL requirement
    Write-Host "Enforcing CTRL+ALT+DEL requirement..." -ForegroundColor Cyan
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCAD" /t REG_DWORD /d 0 /f
    Write-Host "CTRL+ALT+DEL requirement enforced." -ForegroundColor Green

    # Enable Microsoft network client: Digitally sign communications (always)
    Write-Host "Enabling Microsoft network client: Digitally sign communications (always)..." -ForegroundColor Cyan
    reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
    Write-Host "Microsoft network client: Digitally sign communications (always) enabled." -ForegroundColor Green

    # Switch to the secure desktop when prompting for elevation
    Write-Host "Switching to the secure desktop when prompting for elevation..." -ForegroundColor Cyan
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f
    Write-Host "Secure desktop for elevation prompts enabled." -ForegroundColor Green

    Write-Host "`n--- Start Device Policy ---" -ForegroundColor Cyan
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1
    Write-Host "`n--- Local Policies Applied ---`n" -ForegroundColor Cyan
}

function EnableDefensiveCountermeasures {
    Write-Host "`n--- Enabling Defensive Countermeasures ---`n" -ForegroundColor Cyan

    # Enable Firewall Protection
    Write-Host "Enabling Windows Firewall protection..." -ForegroundColor Cyan
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Host "Windows Firewall protection enabled for all profiles." -ForegroundColor Green
    } catch {
        Write-Host "Failed to enable Windows Firewall protection: $_" -ForegroundColor Red
    }

    # Check if Screen Saver is Secure
    Write-Host "Checking and securing screen saver settings..." -ForegroundColor Cyan
    try {
        reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
        reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f
        reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 900 /f
        Write-Host "Screen saver is now secure and set to activate after 15 minutes." -ForegroundColor Green
    } catch {
        Write-Host "Failed to secure screen saver settings: $_" -ForegroundColor Red
    }

    # Disable AutoRun Commands for All Users
    Write-Host "Disabling AutoRun commands for all users..." -ForegroundColor Cyan
    try {
        reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
        Write-Host "AutoRun commands have been disabled for all users." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable AutoRun commands: $_" -ForegroundColor Red
    }

    Write-Host "`n--- Defensive Countermeasures Completed ---`n" -ForegroundColor Cyan
}

function UncategorizedOSSettings {
    Write-Host "`n--- Starting: Uncategorized OS Settings ---`n" -ForegroundColor Cyan

    try {
        # Disable Remote Assistance
        Write-Host "Disabling Remote Assistance connections..." -ForegroundColor Yellow
        $raKey = "HKLM:\System\CurrentControlSet\Control\Remote Assistance"
        if (-not (Test-Path $raKey)) {
            New-Item -Path $raKey -Force | Out-Null
        }
        Set-ItemProperty -Path $raKey -Name fAllowToGetHelp -Value 0 -Force

        # Verify
        $raStatus = (Get-ItemProperty -Path $raKey -Name fAllowToGetHelp).fAllowToGetHelp
        if ($raStatus -eq 0) {
            Write-Host " Remote Assistance is disabled." -ForegroundColor Green
        } else {
            Write-Host " Failed to disable Remote Assistance." -ForegroundColor Red
        }
    } catch {
        Write-Host "Error modifying Remote Assistance settings: $_" -ForegroundColor Red
    }

Write-Host "Disabling AutoRun for all users..." -ForegroundColor Yellow

# Registry path
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Create the registry key if it doesn't exist
If (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

# Optional: Also disable AutoPlay (optional, but often combined)
Set-ItemProperty -Path $regPath -Name "NoAutoRun" -Value 1 -Type DWord

Write-Host "AutoRun has been disabled for all users." -ForegroundColor Green

    Write-Host "`n--- Completed: Uncategorized OS Settings ---`n" -ForegroundColor Cyan
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
    
    # Display the updated status of the service
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

    # Create DOCS folder for logs
    $desktopFolder = [Environment]::GetFolderPath("Desktop")
    $docsFolder = Join-Path $desktopFolder "DOCS"
    if (-not (Test-Path $docsFolder)) {
        New-Item -Path $docsFolder -ItemType Directory -Force | Out-Null
    }
    $logFile = Join-Path $docsFolder ("UpdateLog-" + (Get-Date -Format "yyyy-MM-dd_HH-mm-ss") + ".txt")

    # Trigger Windows Update in background with UsoClient
    try {
        Write-Host "Triggering Windows Update scan, download, and install..." -ForegroundColor $PromptColor
        UsoClient StartScan
        UsoClient StartDownload
        UsoClient StartInstall
        Add-Content -Path $logFile -Value "$(Get-Date) - Updates triggered with UsoClient."
        Write-Host "Updates triggered successfully. Log saved to: $logFile" -ForegroundColor $EmphasizedNameColor

        # Wait for updates to complete installation
        Write-Host "Waiting for updates to complete installation..." -ForegroundColor Yellow
        $updatesInProgress = $true
        while ($updatesInProgress) {
            Start-Sleep -Seconds 30
            $updateStatus = UsoClient ScanInstallWait
            if ($updateStatus -notmatch "Updates in progress") {
                $updatesInProgress = $false
            }
        }
        Write-Host "Updates installed successfully." -ForegroundColor Green

        # Prompt for reboot
        $rebootAnswer = Read-Host "Updates completed. Do you want to reboot now? [Y/n] (default Y)"
        if ($rebootAnswer -eq 'n' -or $rebootAnswer -eq 'N') {
            Write-Host "System reboot skipped. Please remember to restart manually." -ForegroundColor $PromptColor
        } else {
            Write-Host "Rebooting system in 15 seconds to complete updates..." -ForegroundColor $WarningColor
            shutdown.exe /r /t 15 /c "Rebooting to finish Windows Updates"
            Write-Host "You can cancel reboot with 'shutdown.exe /a' if needed." -ForegroundColor $PromptColor
        }
    } catch {
        Write-Host "UsoClient failed: $($_.Exception.Message)" -ForegroundColor $WarningColor
        Add-Content -Path $logFile -Value "$(Get-Date) - Failed to trigger updates: $($_.Exception.Message)"
    }

   Write-Host "`n--- Enabling Updates for Other Microsoft Products ---`n" -ForegroundColor Cyan

    try {
        # Enable Microsoft Update
        reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "AllowMUUpdateService" /t REG_DWORD /d 1 /f
        Write-Host "Updates for other Microsoft products have been enabled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to enable updates for other Microsoft products: $_" -ForegroundColor Red
    }

    Write-Host "`n--- OS Updates process completed ---`n" -ForegroundColor $HeaderColor
}

function Application-Updates {
Write-Host "`n--- Starting: Application Updates ---`n" -ForegroundColor Cyan


# Ensure Winget Installed or Available
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "Winget not found. Attempting installation..." -ForegroundColor Yellow

    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Build -lt 16299)) {
        Write-Host "Winget not supported on this OS version. Skipping installation." -ForegroundColor Red
    } else {
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }

        try {
            choco install winget -y
            refreshenv
        } catch {
            Write-Warning "Chocolatey installation of winget failed: $_"
        }

        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
                Write-Host "Installing Scoop..." -ForegroundColor Cyan
                Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                iex (new-object net.webclient).downloadstring('https://get.scoop.sh')
            }

            try {
                scoop install winget
            } catch {
                Write-Warning "Scoop installation of winget failed: $_"
            }
        }
    }
}

# Refresh PATH just in case
$env:Path += ";$env:LOCALAPPDATA\Microsoft\WindowsApps"

Write-Host "`n--- Detecting Installed Applications ---`n" -ForegroundColor Cyan

# Attempt to detect installed apps
$installedApps = @()
try {
    $installedApps = winget list | Where-Object { $_ -and $_ -notmatch "No installed package" }
} catch {
    Write-Warning "Unable to retrieve installed apps via winget."
}

if (-not $installedApps) {
    Write-Host "No applications detected with Winget. Trying Chocolatey..." -ForegroundColor Yellow
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        $installedApps = choco list --localonly
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        $installedApps = scoop list
    }
}

if (-not $installedApps) {
    Write-Warning "No installed applications could be detected."
    return
}

# Common browsers to check
$browsers = @("Google Chrome", "Microsoft Edge", "Mozilla Firefox", "Brave", "Opera", "Vivaldi")

Write-Host "`n--- Checking for Application Updates ---`n" -ForegroundColor Cyan

# Winget first
$updatesAvailable = winget upgrade | Where-Object { $_ -and $_ -notmatch "No installed package found" }

if (-not $updatesAvailable) {
    Write-Host "No application updates available via Winget." -ForegroundColor Green
} else {
    $updatesAvailable | ForEach-Object {
        if ($_ -match '^\s*(.*?)\s{2,}(.*?)\s{2,}(.*?)\s{2,}(.*?)\s*$') {
            $appName = $matches[1].Trim()
            $current = $matches[2].Trim()
            $latest = $matches[3].Trim()
            $id = $matches[4].Trim()

            $isBrowser = $false
            foreach ($browser in $browsers) {
                if ($appName -like "*$browser*") { $isBrowser = $true }
            }

            $color = if ($isBrowser) { "Magenta" } else { "Yellow" }
            Write-Host "`nUpdate available for: $appName (Current: $current, New: $latest)" -ForegroundColor $color
            $choice = Read-Host "Update this app? [Y/n]"

            if ($choice -eq 'n' -or $choice -eq 'N') {
                Write-Host "Skipped: $appName" -ForegroundColor DarkYellow
            } else {
                try {
                    winget upgrade --id "$id" --accept-package-agreements --accept-source-agreements
                    Write-Host " Updated: $appName" -ForegroundColor Green
                } catch {
                    Write-Warning "Failed to update ${appName}: $_"
                }
            }
        }
    }
}

# Fallback to Chocolatey if Winget didn’t update anything
if ($updatesAvailable.Count -eq 0 -and (Get-Command choco -ErrorAction SilentlyContinue)) {
    try {
        Write-Host "Attempting to update apps with Chocolatey..." -ForegroundColor Cyan
        choco upgrade all -y
    } catch {
        Write-Warning "Chocolatey update process failed: $_"
    }
}

# Fallback to Scoop if needed
if ($updatesAvailable.Count -eq 0 -and (Get-Command scoop -ErrorAction SilentlyContinue)) {
    try {
        Write-Host "Attempting to update apps with Scoop..." -ForegroundColor Cyan
        scoop update *
    } catch {
        Write-Warning "Scoop update process failed: $_"
    }
}

# Ask about browser reinstalls
foreach ($browser in $browsers) {
    $choice = Read-Host "`nWould you like to reinstall $browser? [y/N]"
    if ($choice -eq 'y' -or $choice -eq 'Y') {
        try {
            $pkg = winget list --name "$browser" | Select-String "$browser"
            if ($pkg) {
                Write-Host "Uninstalling $browser..." -ForegroundColor Yellow
                winget uninstall --name "$browser" --accept-package-agreements --accept-source-agreements
                Start-Sleep -Seconds 5
            }
            Write-Host "Installing $browser..." -ForegroundColor Cyan
            winget install --name "$browser" --accept-package-agreements --accept-source-agreements
            Write-Host "$browser successfully reinstalled." -ForegroundColor Green
        } catch {
            Write-Warning "Error reinstalling ${browser}: $_"
        }
    }
}

Write-Host "`n--- Application Update Process Completed ---`n" -ForegroundColor Cyan
}
function Prohibited-Files {
    param (
        [string[]]$PathsToCheck = @("C:\Users"),
        [string[]]$ProhibitedPatterns = @("*.exe", "*.bat", "*.cmd", "*.scr", ".txt")
    )

    Write-Host "Starting scan for prohibited files..." -ForegroundColor Cyan
 # Define prohibited file patterns
    $prohibitedPatterns = @("*.mp3", "*password*", "*cracker*")

    # Define directories to scan
    $directoriesToScan = @("C:\Users", "C:\")

    foreach ($directory in $directoriesToScan) {
        foreach ($pattern in $prohibitedPatterns) {
            try {
                $files = Get-ChildItem -Path $directory -Recurse -Filter $pattern -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-Host "Removed prohibited file: $($file.FullName)" -ForegroundColor Green
                }
            } catch {
                Write-Host "Failed to remove files matching pattern '$pattern' in directory '$directory': $_" -ForegroundColor Red
            }
        }
    }
    
    foreach ($path in $PathsToCheck) {
        foreach ($pattern in $ProhibitedPatterns) {
            try {
                $foundFiles = Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                if ($foundFiles) {
                    Write-Host "Prohibited files found matching pattern '$pattern' in '$path':" -ForegroundColor Red
                    foreach ($file in $foundFiles) {
                        Write-Host $file.FullName -ForegroundColor Yellow

                        if ($file.Name -ieq "users.txt") {
                            # Always remove clear text password file without asking
                            try {
                                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                                Write-Host " Deleted prohibited clear text password file: $($file.FullName)" -ForegroundColor Green
                            } catch {
                                Write-Warning "Failed to delete $($file.FullName): $_"
                            }
                        } else {
                            # Ask for confirmation before removing other prohibited files
                            $response = Read-Host "Do you want to delete this file? (Y/N)"
                            if ($response -match '^[Yy]$') {
                                try {
                                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                                    Write-Host "Deleted: $($file.FullName)" -ForegroundColor Green
                                } catch {
                                    Write-Warning "Failed to delete $($file.FullName): $_"
                                }
                            } else {
                                Write-Host "Skipped: $($file.FullName)" -ForegroundColor Cyan
                            }
                        }
                    }
                } else {
                    Write-Host "No prohibited files matching '$pattern' found in '$path'." -ForegroundColor Green
                }
            } catch {
                Write-Warning "Error scanning $path for pattern $pattern : $_"
            }
        }
    }

    Write-Host "Prohibited files scan completed." -ForegroundColor Cyan
}

function Unwanted-Software {
    Write-Host "`n--- Starting: Unwanted Software Cleanup ---`n" -ForegroundColor Cyan

    # --- Uninstall Angry IP Scanner ---
    $angryIPPath = "C:\Program Files\Angry IP Scanner\uninstall.exe"
    if (Test-Path $angryIPPath) {
        Write-Host "Uninstalling Angry IP Scanner..." -ForegroundColor Yellow
        try {
            Start-Process -FilePath $angryIPPath -ArgumentList "/S" -Wait -ErrorAction Stop
            Write-Host "Angry IP Scanner uninstalled successfully." -ForegroundColor Green
        } catch {
            Write-Host "Failed to uninstall Angry IP Scanner: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Angry IP Scanner is not installed." -ForegroundColor Gray
    }

    # --- Remove Everything FTP root files ---
    $everythingPath = "C:\inetpub\ftproot\Everything"
    if (Test-Path $everythingPath) {
        Write-Host "Removing all files from $everythingPath..." -ForegroundColor Yellow
        try {
            Get-ChildItem -Path $everythingPath -File -Recurse | Remove-Item -Force
            Write-Host "All files removed from $everythingPath." -ForegroundColor Green
        } catch {
            Write-Host "Failed to remove files from $everythingPath : $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Folder $everythingPath does not exist." -ForegroundColor Gray
    }

    # --- Remove Internet Explorer ---
    Write-Host "`nChecking Internet Explorer status..." -ForegroundColor Yellow
    $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
    Write-Host "Detected Windows version: $osVersion" -ForegroundColor Gray

    $requiresReboot = $false

    if ($osVersion -match '^10\.0') {
        # Windows 10 / 11 family
        $ieFeature = Get-WindowsOptionalFeature -Online | Where-Object FeatureName -like "*Internet-Explorer*"
        if ($ieFeature) {
            foreach ($feature in $ieFeature) {
                if ($feature.State -eq "Enabled") {
                    Write-Host "Disabling feature: $($feature.FeatureName)..." -ForegroundColor Yellow
                    try {
                        Disable-WindowsOptionalFeature -Online -FeatureName $feature.FeatureName -NoRestart -ErrorAction Stop
                        Write-Host " $($feature.FeatureName) disabled successfully." -ForegroundColor Green
                        $requiresReboot = $true
                    } catch {
                        Write-Host " Failed to disable $($feature.FeatureName): $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host " $($feature.FeatureName) already disabled." -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "No Internet Explorer features found (Windows 11 or already removed)." -ForegroundColor Gray
        }
    } else {
        Write-Host "Non-Windows 10/11 system detected. Manual removal of INTEXP may be required." -ForegroundColor Gray
    }

    # --- Optional reboot if feature was removed ---
    if ($requiresReboot) {
        Write-Host "`nSystem will reboot in 10 seconds to complete INTEXP removal..." -ForegroundColor Red
        shutdown.exe /r /t 10 /c "Rebooting to finish removing Internet Explorer"
    } else {
        Write-Host "`nNo reboot required." -ForegroundColor Green
    }

    # Define unwanted software patterns
    $unwantedSoftwarePatterns = @("*Chicken Invaders*", "*HashCat*")

    # Define directories to scan
    $directoriesToScan = @("C:\Program Files", "C:\Program Files (x86)", "C:\Users")

    foreach ($directory in $directoriesToScan) {
        foreach ($pattern in $unwantedSoftwarePatterns) {
            try {
                $files = Get-ChildItem -Path $directory -Recurse -Filter $pattern -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-Host "Removed unwanted software: $($file.FullName)" -ForegroundColor Green
                }
            } catch {
                Write-Host "Failed to remove files matching pattern '$pattern' in directory '$directory': $_" -ForegroundColor Red
            }
        }
    }
    Write-Host "`n--- Unwanted Software Cleanup Completed ---`n" -ForegroundColor Cyan
}

function Malware {
    <#
    .SYNOPSIS
    Scans the system for malware using Windows Defender and removes detected threats.
    .DESCRIPTION
    Ensures real-time protection is on, runs a full scan, and deletes/quarantines detected malware.
    #>

    Write-Host "`n--- Starting Malware Scan and Cleanup ---`n" -ForegroundColor Cyan

    try {
        # Enable real-time protection
        Write-Host "Ensuring real-time protection is enabled..." -ForegroundColor Yellow
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

        # Ensure Windows Defender service is running
        Write-Host "Ensuring Windows Defender service is running..." -ForegroundColor Yellow
        $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($defenderService -and $defenderService.Status -ne "Running") {
            try {
                Start-Service -Name "WinDefend" -ErrorAction Stop
                Write-Host "Windows Defender service started successfully." -ForegroundColor Green
            } catch {
                Write-Host "Failed to start Windows Defender service: $($_.Exception.Message)" -ForegroundColor Red
                return
            }
        }

        # Run quick system scan
        Write-Host "Running quick system scan. This may take some time..." -ForegroundColor Yellow
        # Enhanced error handling for Start-MpScan
        try {
            Start-MpScan -ScanType QuickScan
        } catch {
            Write-Host "Failed to start malware scan. Please ensure Windows Defender is enabled and no other antivirus software is interfering." -ForegroundColor Red
            Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Yellow
            return
        }

        # Get detected threats
        $threats = Get-MpThreatDetection

        if ($threats -and $threats.Count -gt 0) {
            Write-Host "Detected threats found. Removing..." -ForegroundColor Red
            $threats | ForEach-Object {
                try {
                    Remove-MpThreat -ThreatID $_.ThreatID -ErrorAction Stop
                    Write-Host "Removed threat: $($_.ThreatName)" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to remove threat: $($_.ThreatName) - $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
            Write-Host "All detected threats have been processed." -ForegroundColor Green
        } else {
            Write-Host "No malware detected." -ForegroundColor Green
        }

        Write-Host "`nMalware scan and cleanup completed successfully." -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error during malware scan: $_" -ForegroundColor Red
    }
    
    # Define backdoor patterns
    $backdoorPatterns = @("*backdoor*", "*remoteadmin*", "*rat*")

    # Define directories to scan
    $directoriesToScan = @("C:\Windows", "C:\Program Files", "C:\Program Files (x86)", "C:\Users")

    foreach ($directory in $directoriesToScan) {
        foreach ($pattern in $backdoorPatterns) {
            try {
                $files = Get-ChildItem -Path $directory -Recurse -Filter $pattern -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-Host "Removed backdoor: $($file.FullName)" -ForegroundColor Green
                }
            } catch {
                Write-Host "Failed to remove files matching pattern '$pattern' in directory '$directory': $_" -ForegroundColor Red
            }
        }
    }
     Write-Host "`n--- Malware Removal Completed ---`n" -ForegroundColor Cyan
}

function Application-Security-Settings {
    Write-Host "`n--- Applying Application Security Settings ---`n" -ForegroundColor Cyan

    try {
        # Block App Execution from Temp & Downloads
        Write-Host "Blocking execution from Temp and Downloads folders..." -ForegroundColor Yellow
        $rules = @(
            @{ Id = "AC99F0DB-2DFC-4E08-BA3A-18B632DAFF68"; Path = "$env:USERPROFILE\Downloads\*"; },
            @{ Id = "3B576869-A4EC-4529-8536-B80A7769E899"; Path = "$env:TEMP\*"; }
        )
        foreach ($rule in $rules) {
            Write-Host "Attack Surface Reduction rules must be configured manually for path exclusions: $($rule.Path)" -ForegroundColor Yellow
        }

        # Enable SmartScreen for Microsoft Store apps
        Write-Host "Enabling SmartScreen for Microsoft Store apps..." -ForegroundColor Yellow
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -Force

        # Enable SmartScreen for Edge
        Write-Host "Enabling SmartScreen for Microsoft Edge..." -ForegroundColor Yellow
        $edgeSmartScreenPath = "HKCU:\Software\Microsoft\Edge"
        if (-not (Test-Path $edgeSmartScreenPath)) {
            New-Item -Path $edgeSmartScreenPath -Force | Out-Null
        }
        Set-ItemProperty -Path "$edgeSmartScreenPath" -Name "SmartScreenEnabled" -Value 1 -Force

        # Enable SmartScreen for Windows
        Write-Host "Enabling SmartScreen for Windows..." -ForegroundColor Yellow
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -Force

        # Enable Controlled Folder Access
        Write-Host "Enabling Controlled Folder Access..." -ForegroundColor Yellow
        Set-MpPreference -EnableControlledFolderAccess Enabled

        # Disallow unsigned PowerShell scripts
        Write-Host "Checking PowerShell execution policy..." -ForegroundColor Yellow
        try {
            $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine
            if ($currentPolicy -ne "AllSigned") {
                Write-Host "Setting PowerShell execution policy to AllSigned..." -ForegroundColor Yellow
                Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force
                Write-Host "Execution policy set to AllSigned." -ForegroundColor Green
            } else {
                Write-Host "Execution policy is already AllSigned." -ForegroundColor Green
            }
        } catch {
            Write-Host "Skipping execution policy change due to Group Policy override." -ForegroundColor Yellow
        }

        # Ask to install or remove Internet Explorer
        Write-Host "Do you want to install or remove Internet Explorer? [Install/Remove/Skip]" -ForegroundColor Yellow
        $ieChoice = Read-Host "Enter your choice"
        if ($ieChoice -eq "Install") {
            Write-Host "Installing Internet Explorer..." -ForegroundColor Yellow
            Enable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online -NoRestart
            Write-Host "Internet Explorer installed successfully." -ForegroundColor Green
        } elseif ($ieChoice -eq "Remove") {
            Write-Host "Removing Internet Explorer..." -ForegroundColor Yellow
            Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online -NoRestart
            Write-Host "Internet Explorer removed successfully." -ForegroundColor Green
        } else {
            Write-Host "Skipped Internet Explorer configuration." -ForegroundColor Yellow
        }

        # Enable Firefox Popup Blocker
Write-Host "Enabling Firefox Popup Blocker (removing any existing dom.disable_open_during_load lines)..." -ForegroundColor Yellow

$firefoxPrefsPath = "$env:APPDATA\Mozilla\Firefox\Profiles"

if (Test-Path $firefoxPrefsPath) {
    $prefsFiles = Get-ChildItem -Path $firefoxPrefsPath -Filter "prefs.js" -Recurse

    foreach ($prefsFile in $prefsFiles) {
        # Read all lines and filter out any that contain the target preference
        $lines = Get-Content $prefsFile | Where-Object { $_ -notmatch "dom\.disable_open_during_load" }

        # Write the filtered content back to the file
        $lines | Set-Content $prefsFile

        Write-Host "Removed dom.disable_open_during_load entry from: $($prefsFile.FullName)" -ForegroundColor Green
    }
} else {
    Write-Host "Firefox preferences not found. Skipping popup blocker configuration." -ForegroundColor Yellow
}


        Write-Host "`nApplication security settings applied successfully." -ForegroundColor Green
    } catch {
        Write-Host "Error applying application security settings: $_" -ForegroundColor Red
    }
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
            # Display incomplete options in default colors
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
            AuditUsers 
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
            EnableDefensiveCountermeasures 
            $completedOptions += $menuOptions[5]  # Mark as completed
        }
        "7"  { 
            UncategorizedOSSettings 
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
}
 while ($true)
