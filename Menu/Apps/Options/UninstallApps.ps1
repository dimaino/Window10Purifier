function Title
{
	param
	(
		[string]$Title = 'Uninstall Microsoft Apps'
	)
	cls
	Write-Host "================ $Title ================"
}

Title

$tweaks = @(
	"RequireAdmin",
	"RemoveEditwith3DPaintFromMenu"
	# "RestoreEditwith3DPaintFromMenu"
	# "RemoveCastToDeviceFromMenu"
	# "InstallPhotoViewer",
	# "UninstallAllExceptThese"
	# "DisableOneDrive",
	# "UninstallOneDrive",
	#"UninstallMsftBloat",
	#"UninstallThirdPartyBloat",
	#"UninstallWindowsStore",
	#"DisableXboxFeatures",
	# "DisableAdobeFlash",
	# "UninstallMediaPlayer",
	# "UninstallInternetExplorer",
	# "UninstallWorkFolders",
	# "InstallLinuxSubsystem",
	# "InstallHyperV",
	#"SetPhotoViewerAssociation",
	# "AddPhotoViewerOpenWith",
	# "UninstallPDFPrinter",
	# "UninstallXPSPrinter",
	# "RemoveFaxPrinter"
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

Function RestoreEditwith3DPaintFromMenu {
	Write-Output $PSScriptRoot
	reg import $PSScriptRoot\Restore1.reg
}
Function RemoveCastToDeviceFromMenu {
	Write-Output $PSScriptRoot
	reg import $PSScriptRoot\RemoveCasttoDevice.reg
}

# Install PhotoViewer
Function InstallPhotoViewer {
	Write-Output $PSScriptRoot
	reg import $PSScriptRoot\ActivateWindowsPhotoViewer.reg
}

# Disable OneDrive
Function DisableOneDrive {
	Write-Output "Disabling OneDrive..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
}

# Uninstall OneDrive - Not applicable to Server
Function UninstallOneDrive {
	Write-Output "Uninstalling OneDrive..."
	Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
}

# Uninstall default Microsoft applications
Function UninstallMsftBloat {
	Write-Output "Uninstalling default Microsoft applications..."
	Get-AppxPackage -AllUsers "Microsoft.3DBuilder" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Advertising.Xaml" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.AppConnector" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.BingFinance" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.BingNews" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.BingSports" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.BingTranslator" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.BingWeather" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.CommsPhone" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.GetHelp" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Getstarted" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.HEIFImageExtension" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Messaging" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.MinecraftUWP" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.MixedReality.Portal" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.MSPaint" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Office.OneNote" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Office.Sway" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.OneConnect" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.People" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Print3D" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.RemoteDesktop" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.ScreenSketch" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.SkypeApp" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.VP9VideoExtensions" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Wallet" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.WebpImageExtension" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.WebMediaExtensions" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Windows.ParentalControls" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Windows.PeopleExperienceHost" | Remove-AppxPackage
	#Get-AppxPackage -AllUsers "Microsoft.WindowsCalculator" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.WindowsAlarms" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.WindowsCamera" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "microsoft.windowscommunicationsapps" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.WindowsMaps" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.WindowsPhone" | Remove-AppxPackage
	#Get-AppxPackage -AllUsers "Microsoft.Windows.Photos" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.YourPhone" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.ZuneMusic" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.ZuneVideo" | Remove-AppxPackage
	#Get-AppxPackage -AllUsers "Windows.CBSPreview" | Remove-AppxPackage
}

# Uninstall all application except for these
function UninstallAllExceptThese {
	Get-AppxPackage -AllUsers | where-object {$_.name -notlike "Microsoft.NET.Native.Runtime.1.7"} |
 		where-object {$_.name -notlike "Microsoft.NET.Native.Runtime.2.2"} |
 		where-object {$_.name -notlike "Microsoft.WindowsStore"} |
 		where-object {$_.name -notlike "Microsoft.StorePurchaseApp"} |
		where-object {$_.name -notlike "Microsoft.DirectXRuntime"} |
		where-object {$_.name -notlike "Microsoft.WindowsCalculator"} |
		where-object {$_.name -notlike "1527c705-839a-4832-9118-54d4Bd6a0c89"} |
		where-object {$_.name -notlike "c5e2524a-ea46-4f67-841f-6a9465d9d515"} |
		where-object {$_.name -notlike "E2A4F912-2574-4A75-9BB0-0D023378592B"} |
		where-object {$_.name -notlike "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE"} |
		where-object {$_.name -notlike "InputApp"} |
		where-object {$_.name -notlike "Microsoft.AccountsControl"} |
		where-object {$_.name -notlike "Microsoft.AsyncTextService"} |
		where-object {$_.name -notlike "Microsoft.BioEnrollment"} |
		where-object {$_.name -notlike "Microsoft.CredDialogHost"} |
		where-object {$_.name -notlike "Microsoft.ECApp"} |
		where-object {$_.name -notlike "windows.immersivecontrolpanel"} |
		where-object {$_.name -notlike "Microsoft.NET.Native.Runtime.2.2"} |
		where-object {$_.name -notlike "Microsoft.NET.Native.Framework.2.2"} |
		where-object {$_.name -notlike "Microsoft.NET.Native.Framework.1.7"} |
		where-object {$_.name -notlike "Microsoft.NET.Native.Runtime.2.1"} |
		where-object {$_.name -notlike "Microsoft.NET.Native.Framework.2.1"} |
		where-object {$_.name -notlike "Microsoft.Windows.Cortana"} |
		where-object {$_.name -notlike "Windows.PrintDialog"} |
		where-object {$_.name -notlike "Microsoft.Windows.StartMenuExperienceHost"} |
		where-object {$_.name -notlike "Microsoft.Windows.ShellExperienceHost"} |
		where-object {$_.name -notlike "Microsoft.AAD.BrokerPlugin"} |
		where-object {$_.name -notlike "Microsoft.MicrosoftEdge"} |
		where-object {$_.name -notlike "Microsoft.Windows.CloudExperienceHost"} |
		where-object {$_.name -notlike "Microsoft.Windows.ContentDeliveryManager"} |
		where-object {$_.name -notlike "Windows.CBSPreview"} |
		where-object {$_.name -notlike "Microsoft.XboxGameCallableUI"} |
		where-object {$_.name -notlike "Microsoft.Windows.XGpuEjectDialog"} |
		where-object {$_.name -notlike "Microsoft.Windows.SecureAssessmentBrowser"} |
		where-object {$_.name -notlike "Microsoft.Windows.SecHealthUI"} |
		where-object {$_.name -notlike "Microsoft.Windows.PinningConfirmationDialog"} |
		where-object {$_.name -notlike "Microsoft.Windows.PeopleExperienceHost"} |
		where-object {$_.name -notlike "Microsoft.Windows.ParentalControls"} |
		where-object {$_.name -notlike "Microsoft.Windows.OOBENetworkConnectionFlow"} |
		where-object {$_.name -notlike "Microsoft.Windows.OOBENetworkCaptivePortal"} |
		where-object {$_.name -notlike "Microsoft.Windows.NarratorQuickStart"} |
		where-object {$_.name -notlike "Microsoft.Windows.CapturePicker"} |
		where-object {$_.name -notlike "Microsoft.Windows.CallingShellApp"} |
		where-object {$_.name -notlike "Microsoft.Windows.AssignedAccessLockApp"} |
		where-object {$_.name -notlike "Microsoft.Windows.Apprep.ChxApp"} |
		where-object {$_.name -notlike "Microsoft.Win32WebViewHost"} |
		where-object {$_.name -notlike "Microsoft.PPIProjection"} |
		where-object {$_.name -notlike "Microsoft.MicrosoftEdgeDevToolsClient"} |
		where-object {$_.name -notlike "Microsoft.LockApp"} |
		where-object {$_.name -notlike "Microsoft.UI.Xaml.2.2"} |
		where-object {$_.name -notlike "Microsoft.VCLibs.140.00"} |
		Remove-AppxPackage
}


# Uninstall default third party applications
function UninstallThirdPartyBloat {
	Write-Output "Uninstalling default third party applications..."
	Get-AppxPackage -AllUsers "2414FC7A.Viber" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "46928bounde.EclipseManager" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "4DF9E0F8.Netflix" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "64885BlueEdge.OneCalendar" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "9E2F88E3.Twitter" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "A278AB0D.MarchofEmpires" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "CAF9E577.Plex" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Drawboard.DrawboardPDF" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Facebook.Facebook" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "KeeperSecurityInc.Keeper" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "king.com.BubbleWitch3Saga" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "XINGAG.XING" | Remove-AppxPackage
}

# Uninstall Windows Store
Function UninstallWindowsStore {
	Write-Output "Uninstalling Windows Store..."
	Get-AppxPackage -AllUsers "Microsoft.WindowsStore" | Remove-AppxPackage
}

# Disable Xbox features
Function DisableXboxFeatures {
	Write-Output "Disabling Xbox features..."
	Get-AppxPackage -AllUsers "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
	Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	#Get-AppxPackage -AllUsers "Microsoft.XboxGameCallableUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}

# Disable built-in Adobe Flash in IE and Edge
Function DisableAdobeFlash {
	Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
}

# Uninstall Windows Media Player
Function UninstallMediaPlayer {
	Write-Output "Uninstalling Windows Media Player..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Internet Explorer
Function UninstallInternetExplorer {
	Write-Output "Uninstalling Internet Explorer..."
	Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
	Write-Output "Uninstalling Work Folders Client..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Linux Subsystem - Applicable to 1607 or newer
Function InstallLinuxSubsystem {
	Write-Output "Installing Linux Subsystem..."
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		# 1607 needs developer mode to be enabled
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
	}
	Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Hyper-V - Not applicable to Home
Function InstallHyperV {
	Write-Output "Installing Hyper-V..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	} Else {
		Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
}

# Set Photo Viewer association for bmp, gif, jpg, png and tif
Function SetPhotoViewerAssociation {
	Write-Output "Setting Photo Viewer association for bmp, gif, jpg, png and tif..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
		New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
		New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
		Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
		Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	}
}

# Add Photo Viewer to "Open with..."
Function AddPhotoViewerOpenWith {
	Write-Output "Adding Photo Viewer to `"Open with...`""
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
}

# Uninstall Microsoft Print to PDF
Function UninstallPDFPrinter {
	Write-Output "Uninstalling Microsoft Print to PDF..."
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Microsoft XPS Document Writer
Function UninstallXPSPrinter {
	Write-Output "Uninstalling Microsoft XPS Document Writer..."
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Remove Default Fax Printer
Function RemoveFaxPrinter {
	Write-Output "Removing Default Fax Printer..."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }