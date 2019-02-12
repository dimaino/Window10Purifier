function Show-Menu
{
	param
	(
		[string]$Title = 'Microsoft App Menu'
	)
	cls
	Write-Host "================ $Title ================" 
	Write-Host "1: Press '1' Uninstall Microsoft Apps."
	Write-Host "2: Press '2' Install Microsoft Apps."
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
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\UninstallApps.ps1"
		}
		'2'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\InstallApps.ps1"
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')