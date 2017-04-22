Param($serviceVMComputerNames, $mgmtDomainAccountUserName, $mgmtSecurityGroupName, $clientSecurityGroupName, $restEndPoint)

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
    # Validate REST End Point parameter
    # todo ipv6 not supported here
    #------------------------------------------
    Log "Validating REST end point ..."

    if($restEndPoint -eq $null -or $restEndPoint.Length -eq 0)
    {
        Log "No REST End Point address was specified."
        [array]$vmNames = GetVMNamesFromComputerTierString $serviceVMComputerNames
        if($vmNames.Length -gt 1)
        {
            Log "Please specify a REST End Point address when deploying a network controller with 3 or more nodes."
            Exit $ErrorCode_Failed 
        }
        else 
        {
            Log "REST End Point is not required for standalone deployments."
            Log "Completed execution of script."
            Exit $ErrorCode_Success 
        }
    }
    else
    {
        # In case of Rest IP, it will be provided in CIDR notation
        $restEndPointWithoutSubnet = $restEndPoint.Split("/")[0]
        $restipSubnetLength = $restEndPoint.split("/")[1]

        $restIP = $null;
        if([System.Net.IPAddress]::TryParse($restEndPointWithoutSubnet, [ref] $restIP))
        {
            Log "Network Controller will be deployed using Rest IP Address $restIP";

            if($restIP.AddressFamily -eq "InterNetworkV6")
            {
                Log "The REST IP Specified is an IPv6 address."
                Log "Please provide an IPv4 REST IP for network controller."
                Exit $ErrorCode_Failed
            }

            if($restipSubnetLength -eq $null)
            {
                Log "Rest IP Subnet was not provided. Using Subnet from NC network adapter."
                $restipSubnetLength = GetLocalHostIPv4Subnet
                Log ("Rest IP Subnet Length = " + $restipSubnetLength)
            }

            $interfaceAlias = $(Get-NetAdapter).Name
            $allocatedIp = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $interfaceAlias
            $allocatedIp = [System.Net.IPAddress]::Parse($allocatedIp.IPAddress)
            $subnetIp1 = GetSubnet -IPAddress $restIP -PrefixLength $restipSubnetLength
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
        else
        {
            Log "Network Controller will be deployed using RestName $restEndPoint";
            $domain = ((Get-WmiObject Win32_ComputerSystem).Domain).ToUpper()
			$restEndPointToCheck = $restEndPoint.ToUpper()
            if($restEndPointToCheck.EndsWith($domain) -eq $false)
            {
                Log "The REST Name specified is not in the same domain as this machine."
                Log "    Rest Name: $restEndPoint"
                Log "    Machine Domain: $domain"
                Log "Please specify a fully qualified REST Name Address in the same domain."
                Exit $ErrorCode_Failed                
            }
        }
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