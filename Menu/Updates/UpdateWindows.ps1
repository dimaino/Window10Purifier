function Show-Menu
{
     param (
           [string]$Title = 'Update Windows'
     )
     Clear-Host
     Write-Host "================ $Title ================"
}

Show-Menu

if($PSVersionTable.PSVersion.Major -eq 5) {
      Write-Host "Checking for Windows Powershell is Installed."
      Install-Module PSWindowsUpdate
      Write-Host "Looking for Windows Update..."
      Get-WindowsUpdate
      Write-Host "Installing all updates and then rebooting..."
      Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot | Out-Null
      Restart-Computer
}
