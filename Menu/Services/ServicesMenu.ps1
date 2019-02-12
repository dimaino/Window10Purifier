function Title
{
	param (
		[string]$Title = 'Services Menu'
	)
	cls
	Write-Host "================ $Title ================"
	Write-Host "1: Press '1' Disable Services."
	Write-Host "2: Press '2' Enable Services."
	Write-Host "Q: Press 'Q' to quit."
}

do
{
	Title
	$input = Read-Host "Please make a selection"
	switch($input)
	{
		'1'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\DisableServices.ps1"
		}
		'2'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\EnableServices.ps1"
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')