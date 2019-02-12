function Title
{
	param (
		[string]$Title = 'Services Menu'
	)
	cls
	Write-Host "================ $Title ================"
	Write-Host "1: Press '1' Check Apps on the PC."
	Write-Host "2: Press '2' Set Static IP."
	Write-Host "3: Press '3' Pin Items to Taskbar/Start Menu."
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
			& "$PSScriptRoot\Options\CheckApp.ps1"
		}
		'2'
		{
			cls
            & "$PSScriptRoot\Options\SetStaticIP.ps1"
		}
		'3'
		{
			cls
			& "$PSScriptRoot\Options\PinItems.ps1"
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')

