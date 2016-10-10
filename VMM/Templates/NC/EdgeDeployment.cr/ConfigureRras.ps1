
# Stops script execution on first error
$ErrorActionPreference = "stop";

# Exit Codes
$ErrorCode_Success = 0;
$ErrorCode_Failed = 1;

try 
{
    Write-Output "Setting up Remote access .."

    Install-RemoteAccess -MultiTenancy -ErrorAction Ignore
    Install-RemoteAccess -RoleType SstpProxy -ErrorAction Ignore
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