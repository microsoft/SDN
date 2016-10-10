# Exit Codes
$ErrorCode_Success = 0;


#------------------------------------------
# Logging helper functions
#------------------------------------------
Function LogTime()
{
    return "[" + (Get-Date -Format o) + "]"
}

Function Log($msg)
{
    Write-Verbose $( $(LogTime) + " " + $msg) -Verbose
}

Function DisableDnsRegistratrion ($adapterName)
{
    Log ("Disable DNS registration on adapter " + $adapterName);
    $tmpNic = get-dnsClient | ? {$_.InterfaceAlias -eq $adapterName}
    if ($tmpNic -ne $null)
    {
        Set-DnsClient $adapterName -RegisterThisConnectionsAddress $false -UseSuffixWhenRegistering $false
    }
}

Function EnableDnsRegistratrion ($adapterName)
{  
    Log ("Enable DNS registration on adapter " + $adapterName);
    $tmpNic = get-dnsClient | ? {$_.InterfaceAlias -eq $adapterName}
    if ($tmpNic -ne $null)
    {
        Set-DnsClient $adapterName -RegisterThisConnectionsAddress $true -UseSuffixWhenRegistering $false
		Set-DnsClient $adapterName -RegisterThisConnectionsAddress $true -UseSuffixWhenRegistering $true
    }
}

Function DisableDnsRegistrationForTransitAndBackEnd()
{
    #TODO Disable dns registration of Transit for MUX
  
    # Disable DNS registration for all unconnected nics
    Log "Disabling dns registration for Transit and BackEnd";
    $adapters = @(get-netadapter | where { $_.Status -eq "Disconnected"});
    if($adapters -ne $null )
    {
        foreach($adapter in $adapters)
        {
            DisableDnsRegistratrion($adapter.Name);
        }
    }

}

Function EnableDnsRegistrationForGatewayMgmtNic()
{
    Log "Enabling dns registration for Gateway management nic";
    $adapters = @(get-netadapter | where { $_.Status -eq "Disconnected"});
    if($adapters -ne $null -and  $adapters.count -eq 2)
    {
        $mgmtNic = @(get-netadapter | where { $_.Status -ne "Disconnected"});
        if($mgmtNic -ne $null -and $mgmtNic.count -eq 1)
        {
            EnableDnsRegistratrion($mgmtNic.Name);
			ipconfig /registerdns
        }
    }
}

try 
{
    Log "Disabling DNS Registration ..."
    DisableDnsRegistrationForTransitAndBackEnd;

    Log "Enabling DNS Registration for management of gateway..."
    EnableDnsRegistrationForGatewayMgmtNic;

}
catch 
{
    Log "Caught an exception:";
    Log "    Exception Type: $($_.Exception.GetType().FullName)";
    Log "    Exception Message: $($_.Exception.Message)";
    Log "    Exception HResult: $($_.Exception.HResult)";
}  

Log "Completed execution of script."
# Always return success , don't fail the service instance
Exit $ErrorCode_Success   