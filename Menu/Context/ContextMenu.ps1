function Show-Menu
{
	param
	(
		[string]$Title = 'Context Menu'
	)
	cls
	Write-Host "================ $Title ================" 
	Write-Host "1: Press '1' Hide all context changes."
	Write-Host "2: Press '2' Show all context changes."
	Write-Host "Q: Press 'Q' to quit."
}

do
{
	Show-Menu
	$input = Read-Host "Please make a selection"
	switch($input)
	{
		'1'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\HideContext.ps1"
		}
		'2'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\ShowContext.ps1"
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')