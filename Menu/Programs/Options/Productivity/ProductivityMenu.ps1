function Show-Menu
{
     param (
           [string]$Title = 'Productivity Menu'
     )
     cls
     Write-Host "================ $Title ================"
     
     Write-Host "1: Press '1' Install Productivity."
     Write-Host "2: Press '2' Uninstall Productivity."
     Write-Host "Q: Press 'Q' to quit."
}

do
{
     Show-Menu
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           '1' {
                cls
				& "$PSScriptRoot\Options\InstallProductivity.ps1"
           } '2' {
                cls
				& "$PSScriptRoot\Options\UninstallProductivity.ps1"
           } 'q' {
                return
           }
     }
     pause
}
until ($input -eq 'q')