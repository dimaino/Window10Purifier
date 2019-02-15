# Uses the syspin.exe to pin items to the taskbar.
# c:5386		: Pin to Taskbar
# c:5387		: Unpin from Taskbar
# c:51201	: Pin to Start
# c:51394	: Unpin to Start
#.\syspin.exe "C:\Windows\notepad.exe" c:"Pin to taskbar"

$CMD = 'C:\Users\dimaino\PowerShell\GitHub\Window10Changer\Menu\Tools\Options\syspin.exe'
$arg1 = 'C:\Windows\notepad.exe'
$arg2 = 'c:"Unpin from Taskbar"'


& $CMD $arg1 $arg2