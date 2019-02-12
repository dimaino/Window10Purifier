function Show-Menu
{
     param (
           [string]$Title = 'Update Windows'
     )
     cls
     Write-Host "================ $Title ================"
}

Show-Menu

if($PSVersionTable.PSVersion.Major -eq 5) {
	Install-Module -Name PSWindowsUpdate
	Get-Command -module PSWindowsUpdate
	Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d
	Get-WUInstall -MicrosoftUpdate -AcceptAll -AutoReboot
}
