function Show-Menu
{
	param
	(
		[string]$Title = 'Browser Menu'
	)
	cls
	Write-Host "================ $Title ================"
	Write-Host "1: Press '1' Install Browsers."
	Write-Host "2: Press '2' Uninstall Browsers."
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
			& "$PSScriptRoot\Options\InstallBrowsers.ps1"
		}
		'2'
		{
			cls
			& "$PSScriptRoot\Options\UninstallBrowsers.ps1"
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')