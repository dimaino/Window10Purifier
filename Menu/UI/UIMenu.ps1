function Show-Menu
{
	param
	(
		[string]$Title = 'UI Menu'
	)
	cls
	Write-Host "================ $Title ================" 
	Write-Host "1: Press '1' Disable UI Features."
	Write-Host "2: Press '2' Enable UI Features."
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
			& "$PSScriptRoot\Options\DisableUI.ps1"
		}
		'2'
		{
			cls
			& "$PSScriptRoot\Options\EnableUI.ps1"
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')