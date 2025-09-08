# Define menu options
$menuOptions = @(
    "Document the system",
    "Enable updates",
    "User auditing",
    "Exit"
)
function Get-SystemDocumentation {
    Write-Host "`n--- starting: Documenting the system ---`n"
}
function enable-updates {
    Write-Host "`n--- starting: Enabling updates ---`n"
}
function user-auditing {
    Write-Host "`n--- starting: User auditing ---`n"
    # Get all local users except built-in accounts
    $users = Get-LocalUser | Where-Object { $_.Name -notin @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount') }
    foreach ($user in $users) {
        $default = "Y"
        $answer = Read-Host "Is '$($user.Name)' an authorized user? (Y/n) [Default: $default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $default }
        if ($answer -match '^[Nn]') {
            Write-Host "'$($user.Name)' is NOT authorized. Removing user..."
            try {
                Remove-LocalUser -Name $user.Name -ErrorAction Stop
                Write-Host "'$($user.Name)' has been removed."
            } catch {
                Write-Host "Failed to remove '$($user.Name)': $_"
            }
        } else {
            Write-Host "'$($user.Name)' is authorized."
        }
    }
}

# ...existing code...

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
        "3" { user-auditing }
        "4" { Write-Host "`nExiting script..."; exit }
        default { Write-Host "`nInvalid selection. Please try again." }
    }
} while ($true)
# ...existing coder...
