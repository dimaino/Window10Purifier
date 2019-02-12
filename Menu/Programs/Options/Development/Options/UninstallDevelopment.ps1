function Show-Menu
{
     param (
           [string]$Title = 'Uninstall Development'
     )
     cls
     Write-Host "================ $Title ================"
}

Show-Menu