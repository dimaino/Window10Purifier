function Title
{
	param
	(
		[string]$Title = 'Main Menu'
	)
	Clear-Host
	Write-Host "================ $Title ================"
	Write-Host ""
	Write-Host "0: Press '0' Complete Setup."
	Write-Host "1: Press '1' Microsoft Apps."
	Write-Host "2: Press '2' Explorer Options."
	Write-Host "3: Press '3' Functions."
	Write-Host "4: Press '4' Privacy Settings."
	Write-Host "5: Press '5' Programs."
	Write-Host "6: Press '6' Security."
	Write-Host "7: Press '7' Services."
	Write-Host "8: Press '8' UI Changes."
	Write-Host "9: Press '9' Context Menu."
	Write-Host "A: Press 'A' Applications."
	Write-Host "U: Press 'U' Windows Updates."
	Write-Host "T: Press 'T' Tools."
	Write-Host "Q: Press 'Q' to quit."
	Write-Host ""
}

do
{
	Title
	$input = Read-Host "Please make a selection"
	switch($input)
	{
		'0'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Setup\Setup.ps1"
		}
		'1'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Apps\AppMenu.ps1"
		}
		'2'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Explorer\ExplorerMenu.ps1"
		}
		'3'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Functions\FunctionsMenu.ps1"
        }
		'4'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Privacy\PrivacyMenu.ps1"
		}
		'5'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Programs\ProgramsMenu.ps1"
		}
		'6'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Security\SecurityMenu.ps1"
		}
		'7'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Services\ServicesMenu.ps1"
		}
		'8'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\UI\UIMenu.ps1"
		}
		'u'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Updates\UpdateWindows.ps1"
		}
		'9'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Context\ContextMenu.ps1"
		}
		'a'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Applications\ApplicationMenu.ps1"
		}
		't'
		{
			Clear-Host
			$ScriptPath = Split-Path $MyInvocation.InvocationName
			& "$ScriptPath\Tools\ToolsMenu.ps1"
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')