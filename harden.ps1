# Check if the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Relaunching with elevated privileges..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Define menu options
$menuOptions = @(
    "Document the system",
    "Enable updates",
    "User auditing",
    "Exit",
    "Authorized Administrator"
)

function Get-SystemDocumentation {
    Write-Host "`n--- starting: Documenting the system ---`n"
}

function enable-updates {
    Write-Host "`n--- starting: Enabling updates ---`n"
}

function Invoke-UserAuditing {
    Write-Host "`n--- starting: User auditing ---`n" -ForegroundColor Cyan
    
    # Get all local users except built-in accounts
    $users = Get-LocalUser | Where-Object { 
        $_.Name -notin @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount') -and
        -not $_.PrincipalSource -eq 'MicrosoftAccount'
    }

    if (-not $users) {
        Write-Host "No local user accounts found to audit." -ForegroundColor Yellow
        return
    }

    foreach ($user in $users) {
        $default = "Y"
        Write-Host "User: $($user.Name)" -ForegroundColor Green
        Write-Host "Enabled: $($user.Enabled)" -ForegroundColor Gray
        Write-Host "Last Logon: $($user.LastLogon)" -ForegroundColor Gray
        
        $answer = Read-Host "Is this an authorized user? (Y/n) [Default: $default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $default }
        
        if ($answer -match '^[Nn]') {
            Write-Host "`nRemoving unauthorized user '$($user.Name)'..." -ForegroundColor Yellow
            try {
                Remove-LocalUser -Name $user.Name -ErrorAction Stop
                Write-Host "Successfully removed '$($user.Name)'`n" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove '$($user.Name)': $_`n" -ForegroundColor Red
            }
        } else {
            Write-Host "User '$($user.Name)' is authorized.`n" -ForegroundColor Green
        }
    }
}

function Get-AuthorizedAdministrator {
    Write-Host "`n--- starting: Authorized Administrator auditing ---`n" -ForegroundColor Cyan

    # Get all users in the Administrators group
    $adminGroup = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.ObjectClass -eq "User" }

    if (-not $adminGroup) {
        Write-Host "No administrator accounts found to audit." -ForegroundColor Yellow
        return
    }

    foreach ($admin in $adminGroup) {
        $default = "Y"
        Write-Host "Administrator: $($admin.Name)" -ForegroundColor Green
        
        $answer = Read-Host "Is this an authorized administrator? (Y/n) [Default: $default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $default }
        
        if ($answer -match '^[Nn]') {
            Write-Host "`nRemoving unauthorized administrator '$($admin.Name)'..." -ForegroundColor Yellow
            try {
                Remove-LocalUser -Name $admin.Name -ErrorAction Stop
                Write-Host "Successfully removed '$($admin.Name)'`n" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove '$($admin.Name)': $_`n" -ForegroundColor Red
            }
        } else {
            Write-Host "Administrator '$($admin.Name)' is authorized.`n" -ForegroundColor Green
        }
    }
}

# Display menu and handle selection in a loop
do {
    Write-Host "`nSelect an option:`n"
    for ($i = 0; $i -lt $menuOptions.Count; $i++) {
        Write-Host "$($i + 1). $($menuOptions[$i])"
    }

    $selection = Read-Host "`nEnter the number of your choice"

    switch ($selection) {
        "1" { Get-SystemDocumentation }
        "2" { enable-updates }
        "3" { Invoke-UserAuditing }
        "4" { Write-Host "`nExiting script..."; exit }
        "5" { Get-AuthorizedAdministrator }
        default { Write-Host "`nInvalid selection. Please try again." }
    }
} while ($true)
