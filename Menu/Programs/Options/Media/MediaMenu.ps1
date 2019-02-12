function Show-Menu
{
     param (
           [string]$Title = 'Programs Menu'
     )
     cls
     Write-Host "================ $Title ================"
     
     Write-Host "1: Press '1' Install Media."
     Write-Host "2: Press '2' Uninstall Media."
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
		& "$PSScriptRoot\Options\InstallMedia.ps1"
           } '2' {
                cls
		& "$PSScriptRoot\Options\UninstallMedia.ps1"
           } 'q' {
                return
           }
     }
     pause
}
until ($input -eq 'q')