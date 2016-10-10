# In order for the service template to run servicing on this script application
# all parameters need to be passed down to this script. When one of these parameters 
# changes during Set-Template, VMM can detect there is a valid change to this application
# and run servicing scripts to this application.

Param($serviceVMComputerNames, $mgmtSecurityGroupName, $clientSecurityGroupName, $restEndPoint, $mgmtDomainAccountUserName, $mgmtDomainAccountPassword, $diagnosticLogShare, $diagnosticLogShareUsername, $diagnosticLogSharePassword);
 
. ./Helpers.ps1

# Stops script execution on first error
$ErrorActionPreference = "stop"

# Exit Codes
$ErrorCode_Success = 0
$ErrorCode_Failed = 1

try 
{    
    Log "Network Controller has been installed with the following parameters:"
    Log "    serviceVMComputerNames: $serviceVMComputerNames"
    Log "    mgmtSecurityGroupName: $mgmtSecurityGroupName"
    Log "    clientSecurityGroupName: $clientSecurityGroupName"
    Log "    RestEndPoint: $restEndPoint"
    Log "    mgmtDomainAccountUserName: $mgmtDomainAccountUserName"
    Log "    diagnosticLogShare: $diagnosticLogShare"
    Log "    diagnosticLogShareUsername: $diagnosticLogShareUsername"
}
catch 
{
    Log "Caught an exception:"
    Log "    Exception Type: $($_.Exception.GetType().FullName)"
    Log "    Exception Message: $($_.Exception.Message)"
    Log "    Exception HResult: $($_.Exception.HResult)"
} 

TryStopNetworkControllerLogging 

Log "Completed execution of script."
Exit $ErrorCode_Success 