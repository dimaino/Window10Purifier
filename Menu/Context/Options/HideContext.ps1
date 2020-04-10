function Title
{
	param
	(
		[string]$Title = 'Hide Context Menu Items'
	)
	cls
	Write-Host "================ $Title ================"
}

Title

$tweaks = @(
	"RequireAdmin",
	"RemoveEditwith3DPaintFromMenu",
    "RemoveCastToDeviceFromMenu",
    "RemoveShareFromMenu"
)

$RegistryDirectory = Join-Path -Path (Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path) -Parent) -Parent) -ChildPath "RegistryFiles"

Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}
Function RemoveEditwith3DPaintFromMenu {
	Write-Output 'Removing Edit with 3D Paint from the context menu.'
	reg import $RegistryDirectory\RemoveEditwith3DPaintFromMenu.reg
}

Function RemoveCastToDeviceFromMenu {
	Write-Output 'Removing Edit with 3D Paint from the context menu.'
    cmd.exe /c 'REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /V {7AD84985-87B4-4a16-BE58-8B72A5B390F7} /T REG_SZ /D "Play to Menu" /F'

    taskkill /f /im explorer.exe
    Start-Process explorer.exe
}

Function RemoveShareFromMenu {
    Write-Output 'Removing Share button from the context menu.'
    cmd.exe /c 'REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /V {e2bf9676-5f8f-435c-97eb-11607a5bedf7} /F'

    taskkill /f /im explorer.exe
    Start-Process explorer.exe
}

# Call the desired tweak functions
$tweaks | ForEach-Object { Invoke-Expression $_ }