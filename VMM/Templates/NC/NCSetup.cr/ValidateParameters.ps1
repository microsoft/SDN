Param($serviceVMComputerNames, $mgmtDomainAccountUserName, $mgmtSecurityGroupName, $clientSecurityGroupName, $restIP)

. ./Helpers.ps1

# Stops script execution on first error
$ErrorActionPreference = "stop"

# Exit Codes
$ErrorCode_Success = 0
$ErrorCode_Failed = 1

try 
{    
    #------------------------------------------
    # Validate Management Security Group Parameter
    #------------------------------------------
    Log "Validating Management security group.."
    $groupNameOnly =  $mgmtSecurityGroupName.Split("\")
    $groupNameOnly = $groupNameOnly[$groupNameOnly.Length - 1]
    $group = Get-ADGroup -filter "Name -like '$groupNameOnly' -or SamAccountName -like '$groupNameOnly'"
    if($group -eq $null)
    {
        Log "Could not find Management security group with name '$groupNameOnly' in Active Directory."
        Log "Please specify a valid management security group."
        Exit $ErrorCode_Failed 
    }
    
    #------------------------------------------
    # Validate Management Domain Account Parameter
    #------------------------------------------
    Log "Validating Management domain account.."
    $userNameOnly =  $mgmtDomainAccountUserName.Split("\")
    $userNameOnly = $userNameOnly[$userNameOnly.Length - 1]
    $user = Get-ADUser -Filter "Name -like '$userNameOnly' -or SamAccountName -like '$userNameOnly'"
    if($user -eq $null)
    {
        Log "Could not find Management domain account with name '$userNameOnly' in Active Directory."
        Log "Please specify a valid management domain account."
        Exit $ErrorCode_Failed 
    }
    
    #------------------------------------------
    # Validate Client Domain Account Parameter
    #------------------------------------------
    Log "Validating Client security group.."
    $groupNameOnly =  $clientSecurityGroupName.Split("\")
    $groupNameOnly = $groupNameOnly[$groupNameOnly.Length - 1]
    $group = Get-ADGroup -filter "Name -like '$groupNameOnly' -or SamAccountName -like '$groupNameOnly'"
    if($group -eq $null)
    {
        Log "Could not find client security group with name '$groupNameOnly' in Active Directory."
        Log "Please specify a valid client security group."
        Exit $ErrorCode_Failed 
    }
    
    #------------------------------------------
    # Validate REST IP Address parameter
    # todo ipv6 not supported here
    #------------------------------------------
    Log "Validating REST IP Address.."
    if($restIP -eq $null -or $restIP.Length -eq 0)
    {
        Log "No REST IP address was specified."
        [array]$vmNames = GetVMNamesFromComputerTierString $serviceVMComputerNames
        if($vmNames.Length -gt 1)
        {
            Log "Please specify a REST IP address when deploying a network controller with 3 or more nodes."
            Exit $ErrorCode_Failed 
        }
        else 
        {
            Log "REST IP is not required for standalone deployments."
            Log "Completed execution of script."
            Exit $ErrorCode_Success 
        }
    }
    
    if(-not $restIP.contains("/"))
    {
        Log "The REST IP Address specified is not in CIDR notation."
        Log "Please specify a valid REST IP Address in the format <IP Address>/<Subnet Length>."
        Exit $ErrorCode_Failed 
    }
    
    $restipAddress = $restIP.split("/")[0]
    $restipSubnetLength = $restIP.split("/")[1]
    
    $ipAlreadyExists = Get-NetIPAddress | where {$_.IPAddress -eq $restipAddress}
    if($ipAlreadyExists -ne $null)
    {
        Log "The REST IP Address specified is already allocated to this machine."
        Log "Please specify a REST IP Address that is not already in use."
        Exit $ErrorCode_Failed 
    }
    
    if($restipAddress -like "169.254*")
    {
        Log "The REST IP Address specifies an invalid IP that cannot be used."
        Log "Please specify a valid REST IP Address."
        Exit $ErrorCode_Failed 
    }
    
    $interfaceAlias = $(Get-NetAdapter).Name
    $restipAddress = [System.Net.IPAddress]::Parse($restipAddress)
    $allocatedIp = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $interfaceAlias
    $allocatedIp = [System.Net.IPAddress]::Parse($allocatedIp.IPAddress)
    $subnetIp1 = GetSubnet -IPAddress $restipAddress -PrefixLength $restipSubnetLength
    $subnetIp2 = GetSubnet -IPAddress $allocatedIp -PrefixLength $restipSubnetLength
    if($subnetIp1 -ne $subnetIp2)
    {
        Log "The REST IP Address specified is not in the same subnet as the IP allocated to this machine."
        Log "    REST IP subnet: $subnetIp1"
        Log "    Machine subnet: $subnetIp2"
        Log "Please specify a REST IP Address in the same subnet."
        Exit $ErrorCode_Failed 
    }
}
catch 
{
    Log "Caught an exception:"
    Log "    Exception Type: $($_.Exception.GetType().FullName)"
    Log "    Exception Message: $($_.Exception.Message)"
    Log "    Exception HResult: $($_.Exception.HResult)"
    Exit $($_.Exception.HResult)
}  

Log "Completed execution of script."
Exit $ErrorCode_Success 