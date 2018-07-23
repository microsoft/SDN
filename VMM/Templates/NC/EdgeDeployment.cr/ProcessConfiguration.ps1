
# Stops script execution on first error
$ErrorActionPreference = "stop";

# Exit Codes
$ErrorCode_Success = 0;
$ErrorCode_Failed = 1;

try 
{
    Write-Output "Installing RemoteAccess related powershell modules ..."

    Add-WindowsFeature RemoteAccess -IncludeAllSubFeature -IncludeManagementTools
    Add-WindowsFeature DirectAccess-VPN
    Add-WindowsFeature Routing

    Write-Output "Creating a firewall rule to allow inbound traffic for port 5986 (Wsman HTTPS)"
    New-NetFirewallRule -DisplayName "GW Allow TCP port 5986" -Name "Allow-5986" -Description "allow inbound traffic for port 5986 (Wsman HTTPS)" -Protocol TCP -LocalPort 5986 -Enabled True -Profile Any -Action Allow
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