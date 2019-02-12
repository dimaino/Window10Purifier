function Show-Menu
{
     param (
           [string]$Title = 'Install Everything'
     )
     cls
     Write-Host "================ $Title ================"
}

Show-Menu