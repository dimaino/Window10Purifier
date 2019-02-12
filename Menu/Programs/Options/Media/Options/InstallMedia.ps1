function Show-Menu
{
     param (
           [string]$Title = 'Install Media'
     )
     cls
     Write-Host "================ $Title ================"
}

Show-Menu