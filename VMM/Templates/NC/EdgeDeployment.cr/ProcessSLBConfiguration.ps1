# Exit Codes
$ErrorCode_Success = 0;

try 
{
    Write-Output "Installing Software Load Balancer Windows feature ..."
    Install-WindowsFeature -Name SoftwareLoadBalancer -IncludeAllSubFeature -IncludeManagementTools
}
catch 
{
    Write-Output "Caught an exception:";
    Write-Output "    Exception Type: $($_.Exception.GetType().FullName)";
    Write-Output "    Exception Message: $($_.Exception.Message)";
    Write-Output "    Exception HResult: $($_.Exception.HResult)";
    Exit $($_.Exception.HResult);
}  

Write-Output "Completed execution of script."
Exit $ErrorCode_Success   