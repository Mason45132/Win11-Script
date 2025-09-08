# Define menu options
$menuOptions = @(
    "Document the system",
    "Enable updates",
    "User Auditing",
    "Exit"
)
# Define functions for each option
function Document-System {
    Write-Host "`n--- Starting: Document the system ---`n"
}

function Enable-Updates {
    Write-Host "`n--- Starting: Enable updates ---`n"
}

function User-Auditing {
    Write-Host "`n--- Starting: User Auditing ---`n"
# Enumerate all local user accounts
$localUsers = Get-LocalUser

foreach ($user in $localUsers) {
    # Skip built-in accounts
    if ($user.Name -in @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')) {
        continue
    }

    $prompt = "Is '$($user.Name)' an Authorized User? [Y/n]: "
    $answer = Read-Host -Prompt $prompt

    if ($answer -eq 'n' -or $answer -eq 'N') {
        try {
            Remove-LocalUser -Name $user.Name
            Write-Host "Deleted user: $($user.Name)"
        } catch {
            Write-Host "Failed to delete user: $($user.Name) - $_"
        }
    } else {
        Write-Host "Kept user: $($user.Name)"
    }
}
# Enumerate all users in the Administrators group
$adminGroup = Get-LocalGroupMember -Group "Administrators"

foreach ($admin in $adminGroup) {
    # Only process user accounts (not groups or service accounts)
    if ($admin.ObjectClass -ne 'User') {
        continue
    }

    $prompt = "Is '$($admin.Name)' an Authorized Administrator? [Y/n]: "
    $answer = Read-Host -Prompt $prompt

    if ($answer -eq 'n' -or $answer -eq 'N') {
        try {
            Remove-LocalGroupMember -Group "Administrators" -Member $admin.Name
            Write-Host "Removed administrator: $($admin.Name)"
        } catch {
            Write-Host "Failed to remove administrator: $($admin.Name) - $_"
        }
    } else {
        Write-Host "Kept administrator: $($admin.Name)"
    }
}
# ...existing code...

# Display the computer's hostname
Write-Host "Computer Name: $env:COMPUTERNAME"

# Display the Windows version
Write-Host "Windows Version:"
Get-ComputerInfo | Select-Object -Property WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer | Format-List
Write-Host "Script Run Time: $(Get-Date)"
# ...existing code...
# Enumerate all local user accounts
$localUsers = Get-LocalUser
}
# Menu loop
:menu do {
    Write-Host "`nSelect an option:`n"
    for ($i = 0; $i -lt $menuOptions.Count; $i++) {
        Write-Host "$($i + 1). $($menuOptions[$i])"
    }

    $selection = Read-Host "`nEnter the number of your choice"

    switch ($selection) {
        "1" { Document-System }
        "2" { Enable-Updates }
        "3" { User-Auditing }
        "4" { Write-Host "`nExiting..."; break menu }  # leave the do{} loop
        default { Write-Host "`nInvalid selection. Please try again." }
    }
} while ($true)
