function Title
{
     param (
           [string]$Title = 'Security Menu'
     )
     cls
     Write-Host "================ $Title ================"
     
     Write-Host "1: Press '1' Disable Security Features."
     Write-Host "2: Press '2' Enable Security Features."
     Write-Host "Q: Press 'Q' to quit."
}

do
{
	Title
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           '1' {
                cls
				$ScriptPath = Get-Location
				& "$PSScriptRoot\Options\DisableSecurityFeatures.ps1"
           } '2' {
                cls
				$ScriptPath = Get-Location
				& "$PSScriptRoot\Options\EnableSecurityFeatures.ps1"
           } 'q' {
                return
           }
     }
     pause
}
until ($input -eq 'q')