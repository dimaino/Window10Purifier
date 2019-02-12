function Show-Menu
{
     param (
           [string]$Title = 'Programs Menu'
     )
     cls
     Write-Host "================ $Title ================"
     
     Write-Host "1: Press '1' Install Games."
     Write-Host "2: Press '2' Uninstall Games."
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
		& "$PSScriptRoot\Options\InstallGames.ps1"
           } '2' {
                cls
		& "$PSScriptRoot\Options\UninstallGames.ps1"
           } 'q' {
                return
           }
     }
     pause
}
until ($input -eq 'q')