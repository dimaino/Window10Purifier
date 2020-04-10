function Show-Menu
{
	param
	(
		[string]$Title = 'Microsoft App Menu'
	)
	cls
	Write-Host "================ $Title ================" 
	Write-Host "1: Press '1' Install Application."
	Write-Host "2: Press '2' Install Microsoft Apps."
	Write-Host "3: Press '3' Install My Apps."
    Write-Host "4: Press '4' Uninstall My Apps."
    Write-host "A: Press 'A' All Applciations."
	Write-Host "Q: Press 'Q' to quit."
}

do
{
	Show-Menu
	$input = Read-Host "Please make a selection"
	switch ($input)
	{
		'1'
		{
			Clear-Host
			& "$PSScriptRoot\Options\UninstallApps.ps1"
		}
		'2'
		{
			Clear-Host
			& "$PSScriptRoot\Options\InstallApps.ps1"
		}
		'3'
		{
			Clear-Host
			& "$PSScriptRoot\Options\ApplicationInstaller.ps1"
		}
		'4'
		{
			Clear-Host
			& "$PSScriptRoot\Options\ApplicationUninstaller.ps1"
        }
        'a'
        {
            Clear-Host
			& "$PSScriptRoot\Options\AllApplications.ps1"
        }
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')