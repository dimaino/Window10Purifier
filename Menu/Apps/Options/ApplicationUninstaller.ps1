$UninstallList = @(
	"UninstallBraveBrowser"
	#"UninstallGoogleChrome",
	#"UninstallFireFox"
)







Function CheckIfInstalled($Software)
{
	$Value = $FALSE
	#Checks if OS Architecture is 64-Bit or 32-Bit
	if ([IntPtr]::Size -eq 4)
	{
        $installed32 = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $Software }) -ne $null
		$installed64 = $FALSE
    }
    else
	{
		$installed32 = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $Software }) -ne $null
		$installed64 = (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where { $_.DisplayName -eq $Software }) -ne $null
    }
	If(-Not $installed32 -and -Not $installed64)
	{
		Write-Host "'$Software' NOT is installed.";
		return $TRUE
	} 
	else
	{
		Write-Host "'$Software' is installed."
		return $FALSE
	}
	return $Value
}

Function UnpinBraveBrowserToTaskBar
{
	if([System.IO.File]::Exists('%appdata%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'))
	{
		$Location = Get-Location
		$CMD = Join-Path -Path $Location -ChildPath "Menu\Tools\Options\syspin.exe"
		$arg1 = 'C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe'
		$arg2 = 'c:"Unpin from Taskbar"'
		& $CMD $arg1 $arg2
	}
	else
	{
		Write-Host "Brave Browser is not pinned to the taskbar."
	}
}


Function UninstallBraveBrowser()
{
	if(CheckIfInstalled('Brave'))
	{
		Write-Host "It appears that Brave Browsers is not installed on this system..."
	}
	else
	{
		UnpinBraveBrowserToTaskBar
		Write-Host "Currently uninstalling Brave Browser..."
		(Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\BraveSoftware Brave-Browser').version | ForEach-Object {& ${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\$_\Installer\setup.exe --uninstall --multi-install --chrome --system-level --force-uninstall}
		Write-Host "Brave Browser unintalled..."
	}
}

# Call the uninstalls
$UninstallList | ForEach { Invoke-Expression $_ }