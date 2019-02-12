function Show-Menu
{
     param (
           [string]$Title = 'Uninstall Media'
     )
     cls
     Write-Host "================ $Title ================"
}

Show-Menu