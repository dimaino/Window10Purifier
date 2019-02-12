######################
# Set IPv4 IP Address			
# Author: Daniel Imaino		
# Version: 1 - 02-11-2019	
######################

$InterfaceAliasName = 'Ethernet'

function Title
{
	param
	(
		[string]$Title = 'Set IP Address Menu'
	)
	cls
	Write-Host "================ $Title ================"
	Write-Host "1: Press '1' Set the IP Address."
	Write-Host "2: Press '2' Set the Subnet you want. (eg. 255.255.255.0)"
	Write-Host "3: Press '3' Set the default gateway."
	Write-Host "4: Press '4' Set the first DNS Address."
	Write-Host "5: Press '5' Set the second DNS Address."
	Write-Host "D: Press 'D' Set the IP Address back to default DHCP."
	Write-Host "N: Press 'N' Find Interface information."
	Write-Host "C: Press 'C' Configures network. (Only works if network is dchp and connect)"
	Write-Host "S: Press 'S' Set interface name."
	Write-Host "Q: Press 'Q' to quit."
}

do
{
	Title
	$input = Read-Host "Please make a selection"
	switch($input)
	{
		'H'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.159' -PrefixLength 25 -DefaultGateway '10.23.46.129'
		}
		'V'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.160' -PrefixLength 25 -DefaultGateway '10.23.46.129'
		}
		'1'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.161' -PrefixLength 25 -DefaultGateway '10.23.46.129'
		}
		'2'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.162' -PrefixLength 25 -DefaultGateway '10.23.46.129'
		}
		'3'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.163' -PrefixLength 25 -DefaultGateway '10.23.46.129'
        }
		'4'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.164' -PrefixLength 25 -DefaultGateway '10.23.46.129'
		}
		'5'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.165' -PrefixLength 25 -DefaultGateway '10.23.46.129'
		}
		'6'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.166' -PrefixLength 25 -DefaultGateway '10.23.46.129'
		}
		'7'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.167' -PrefixLength 25 -DefaultGateway '10.23.46.129'
		}
		'8'
		{
			cls
			Write-Host "Changing IP Information..."
			New-NetIPAddress -InterfaceAlias $InterfaceAliasName -IPAddress '10.23.46.168' -PrefixLength 25 -DefaultGateway '10.23.46.129'
		}
		'D'
		{
			cls
			Write-Host "Changing your IP information back to DHCP..."
			Remove-NetRoute -InterfaceAlias $InterfaceAliasName -NextHop '10.23.46.129' -Confirm:$false
			Set-NetIPInterface -InterfaceAlias $InterfaceAliasName -Dhcp Enabled
			Restart-NetAdapter -InterfaceAlias $InterfaceAliasName
			Start-Sleep -s 2
			Write-Host "Wait a few seconds for the Ethernet Adapter to reset..."
		}
		'N'
		{
			cls
			Get-NetIPInterface -AddressFamily IPv4
		}
		'C'
		{
			cls
			$InterfaceAliasName = Get-NetIPInterface -AddressFamily IPv4 -Dhcp Enabled -ConnectionState Connected | Select-Object -ExpandProperty InterfaceAlias
			Write-Host "The Interface Alias parameter has been set to: "
			Write-Output $InterfaceAliasName
		}
		'S'
		{
			cls
			$InterfaceAliasName = Read-Host "Please enter the Interface Name."
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')