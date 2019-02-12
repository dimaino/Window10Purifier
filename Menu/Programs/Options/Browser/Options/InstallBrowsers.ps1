function Show-Menu
{
     param (
           [string]$Title = 'Install Browsers'
     )
     cls
     Write-Host "================ $Title ================"
}

Show-Menu