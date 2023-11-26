<#
.DESCRIPTION
	Powershell script at end of Freestyle onboarding process, that cleans up things like auto-logon settings, removes the custom Shell and finally reboots the device.

.Author(s):
	Wannes De Boodt - Business Transformation - VMware PSO

.Prerequisites:
	not applicable

.NOTES
	changelog:
	23-04-28 - wannes de boodt - v1.0.8 Modified logging location
#>
#=============================================================
# Parameters
#=============================================================
$logpath = "C:\ProgramData\AirWatch\UnifiedAgent\Logs"
$logfile = "C:\ProgramData\AirWatch\UnifiedAgent\Logs\onboarding.log"
$regTagPath = "HKLM:\SOFTWARE\Customer\Staging\FinalReboot"

#=============================================================
# Create Log Path
#=============================================================
if(-not (Test-Path $logpath)){
    New-Item -ItemType Directory -Path $logfile -Force
}
function Write-Log {
    param($msg)
    "$(Get-Date -Format G) - Main Workflow - cleanup and reboot: $msg" | Out-File -FilePath $logfile -Append -Force
}

#=============================================================
# Shell Launcher Bridge WMI Helper functions
#=============================================================
$NameSpace = "root\cimv2\mdm\dmmap"
$Class = "MDM_AssignedAccess"

function Get-AssignedAccessCspBridgeWmi
{
    return Get-CimInstance -Namespace $NameSpace -ClassName $Class
}

function Clear-ShellLauncherBridgeWMI
{
    Write-Log "reverting custom shell launcher modifications"
	$AssignedAccessCsp = Get-AssignedAccessCspBridgeWmi
    $AssignedAccessCsp.ShellLauncher = $NULL
    Set-CimInstance -CimInstance $AssignedAccessCsp
}

#=============================================================
# Start Cleanup tasks
#=============================================================
function perform-cleanup {
	try
	{
		#renaming local administrator account
        Rename-LocalUser -Name "Administrator" -NewName "NewAdminName"
		
		#Set the autologon count back to zero
		Write-Log "Remove autologon settings"
		Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value ""
		Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value ""
		Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonCount -Value ""

		#remove last logged on user
		Write-Log "remove last logged on user"
		Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnUser -Value ""
		Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedOnSAMUser -Value ""

		#remove custom Shell
		Clear-ShellLauncherBridgeWMI
		Write-Log "removing custom Shell feature"
		Disable-WindowsOptionalFeature -online -FeatureName Client-EmbeddedShellLauncher -NoRestart
		start-sleep 60

		#revert PowerShell ExecutionPolicy to default
		Write-Log "Setting PowerShell ExecutionPolicy to default"
		Set-ExecutionPolicy Restricted -Scope LocalMachine -Force

		#Trigger reboot command
		Write-Log "Triggering final reboot"
		Start-Process -FilePath "cmd.exe" -ArgumentList '/c "timeout /t 270 /nobreak && shutdown -r -f -t 0"' -WindowStyle Hidden

		Write-Log "Cleanup completed"
		return $true
	}
	catch {
		Write-Log "ERRORMSG: " + $_.Exception.Message
        $ErrorMessage = $_.Exception.Message
        $ExitCode = 121
        Add-RegistryCode -ExitCode $ExitCode -ErrorMessage $ErrorMessage
        Add-RegistryHistory
        Exit 121
	}
}

#=============================================================
# Create Logging Regkey for time
#=============================================================

function Add-RegistryHistory {
    Param(
        [Parameter(Mandatory = $false)] $Result
    )
    try {
        if (!(Test-Path $regTagpath)) {
            New-Item -Path $regTagPath -Force | Out-Null
        }

        $successful = $Result
        # The last date and time the script was run regardless if it was successful or not
        $lastExecutionTime = Get-Date -format "MM/dd/yyyy HH:mm"
        Set-ItemProperty -Path $regTagPath -Name "LastExecutionTime" -Value $lastExecutionTime -Force

        if ($successful -eq $true) {
            Set-ItemProperty -Path $regTagPath -Name "ExitCode" -Value "0" -Force
			Set-ItemProperty -Path $regTagPath -Name "ErrorMessage" -Value "" -Force
			Write-Log "Successfully completed the entire staging process"
        }
    }
    catch {
        Write-Log "ERRORMSG: " + $_.Exception.Message
        $ErrorMessage = $_.Exception
        $ExitCode = 100
        Add-RegistryCode -ExitCode $ExitCode -ErrorMessage $ErrorMessage
        Exit 100
    }
}

#=============================================================
# Create Logging Regkey for exit code and error message
#=============================================================

function Add-RegistryCode {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $ExitCode,
        [Parameter(Mandatory = $false)]
        [string] $ErrorMessage
    )

    if (!(Test-Path $regTagpath)) { New-Item -Path $regTagPath -Force }

	New-ItemProperty -Path $regTagPath -Name "ExitCode" -Value $ExitCode -Force
	New-ItemProperty -Path $regTagPath -Name "ErrorMessage" -Value $ErrorMessage -Force
}

#=============================================================
# Script commands start here
#=============================================================
Write-Log "Starting script to cleanup and reboot device"
$result = perform-cleanup
Add-RegistryHistory -Result $Result
