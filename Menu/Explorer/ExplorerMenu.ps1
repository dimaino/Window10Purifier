function Show-Menu
{
	param
	(
		[string]$Title = 'Explorer Option Menu'
	)
	cls
	Write-Host "================ $Title ================" 
	Write-Host "1: Press '1' Hide."
	Write-Host "2: Press '2' Show."
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
			& "$PSScriptRoot\Options\HideExplorer.ps1"
		}
		'2'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\ShowExplorer.ps1"
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')