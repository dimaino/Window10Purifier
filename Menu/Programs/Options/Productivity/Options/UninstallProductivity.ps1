function Show-Menu
{
     param (
           [string]$Title = 'Uninstall Browsers'
     )
     cls
     Write-Host "================ $Title ================"
}

Show-Menu