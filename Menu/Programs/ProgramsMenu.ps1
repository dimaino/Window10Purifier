function Show-Menu
{
	param
	(
		[string]$Title = 'Programs Menu'
	)
	cls
	Write-Host "================ $Title ================"
	Write-Host "0: Press '0' Install Everything."
	Write-Host "1: Press '1' Browser Options."
	Write-Host "2: Press '2' Development Options."
	Write-Host "3: Press '3' Games Options."
	Write-Host "4: Press '4' Media Options."
	Write-Host "5: Press '5' Productivity Options."
	Write-Host "Q: Press 'Q' to quit."
}

do
{
	Show-Menu
	$input = Read-Host "Please make a selection"
	switch($input)
	{
		'0'
		{
			cls
			& "$PSScriptRoot\Options\InstallEverything.ps1"
		}
		'1'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\Browser\BrowserMenu.ps1"
		}
		'2'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\Development\DevelopmentMenu.ps1"
		}
		'3'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\Games\GamesMenu.ps1"
		}
		'4'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\Media\MediaMenu.ps1"
		}
		'5'
		{
			cls
			$ScriptPath = Get-Location
			& "$PSScriptRoot\Options\Productivity\ProductivityMenu.ps1"
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')