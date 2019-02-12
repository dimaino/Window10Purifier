function Show-Menu
{
     param (
           [string]$Title = 'Install Development'
     )
     cls
     Write-Host "================ $Title ================"
}

Show-Menu