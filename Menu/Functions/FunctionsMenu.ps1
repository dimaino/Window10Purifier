function Show-Menu
{
	param
	(
		[string]$Title = 'Functions Menu'
	)
	cls
	Write-Host "================ $Title ================" 
	Write-Host "1: Press '1' Disable Functions."
	Write-Host "2: Press '2' Enable Functions."
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
			& "$PSScriptRoot\Options\DisableFunctions.ps1"
		}
		'2'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\EnableFunctions.ps1"
			}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')