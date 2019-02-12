function Show-Menu
{
     param (
           [string]$Title = 'Install Games'
     )
     cls
     Write-Host "================ $Title ================"
}

Show-Menu