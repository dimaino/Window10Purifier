function Show-Menu
{
	param
	(
		[string]$Title = 'Privacy Menu'
	)
	cls
	Write-Host "================ $Title ================" 
	Write-Host "1: Press '1' Disable Privacy Settings."
	Write-Host "2: Press '2' Enable Privacy Settings."
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
			& "$PSScriptRoot\Options\DisablePrivacySettings.ps1"
		}
		'2'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\EnablePrivacySettings.ps1"
			}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')