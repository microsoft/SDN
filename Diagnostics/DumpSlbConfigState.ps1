param(
    [string]$NCIP = "192.168.0.4",
    [string]$LogPath = "c:\tools\SlbConfigState.txt",
    [switch]$Details = $true
    )

$CurrentPath = Convert-Path .
. c:\tools\CommonFunctions.ps1

cd C:\Windows\NetworkController\SDNCTLR

function WriteLog($Message, $LogPath="")
{
    if ($LogPath -ne "") {
        Out-File -InputObject $Message -FilePath $LogPath -Append
    } else {
        Write-Host $Message
        Write-Output $Message
    }
}

try
{
    if(Test-Path $LogPath)
    {
        del $LogPath
    }

    $buildStringMsg = "NC VM Build = " + (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\").GetValue('BuildLabEx')
    WriteLog $buildStringMsg $LogPath

    $skuMsg = "NC VM SKU = " + (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\").GetValue('EditionID')
    WriteLog $skuMsg $LogPath
}
catch
{
    WriteLog $_ $LogPath
}

try
{
    unregister-event *
    . .\slbclientWin.ps1
}
catch
{
    WriteLog $_ $LogPath
}

$slbclient = New-Object Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbClient

$connectionPoint = new-object System.Net.IPEndPoint([ipaddress]::parse($NCIP), 8550)
$global:slbmConnection = $slbclient.ConnectToSlbManager($connectionPoint, $null, $null) 

WriteLog "####################### MUX & SLBM Info Starts #######################" $LogPath
try
{
    $slbmVip = slb-GetSlbmVips
    if($slbmVip -eq $null) {
        WriteLog "!!! BUG BUG failed to get info using slb-GetSlbmVips" $LogPath
    }
    else {
        $slbmVip >> $LogPath
    }

    $MuxInfo = slb-GetMuxStateDriverInfo
    if($MuxInfo -eq $null) {
        WriteLog "!!! BUG BUG failed to get info using slb-GetMuxStateDriverInfo" $LogPath
    }
    else {
        $MuxInfo >> $LogPath
    }
}
catch
{
    WriteLog $_ $LogPath
    WriteLog "!!! BUG BUG failed to get Mux Information" $LogPath
}
WriteLog "####################### MUX & SLBM Info Ends #######################" $LogPath

WriteLog "####################### Host Info Starts #######################" $LogPath
try
{
    $hostsInfo = $global:slbmConnection.GetConnectedHosts();
    if($hostsInfo -eq $null) {
        WriteLog "!!! BUG BUG failed to get info using slb-GetConnectedHosts" $LogPath
    }
    else {
        $hostCount = $hostsInfo.Count
        WriteLog "Number of Host Connected : $hostCount" $LogPath
        foreach($hostInfo in $hostsInfo){
		WriteLog $hostInfo $LogPath
 	}
    }
}
catch
{
    WriteLog $_ $LogPath
    WriteLog "!!! BUG BUG failed to get Host Information" $LogPath
}
WriteLog "####################### Host Info Ends #######################" $LogPath

WriteLog "####################### MUX Advertized Routes Starts #######################" $LogPath
try
{
    $RouterInfo = slb-GetRouterConfiguration
    if($RouterInfo -eq $null) {
        WriteLog "!!! BUG BUG failed to get info using slb-GetRouterConfiguration" $LogPath
    }
    else {
        $RouterInfo >> $LogPath
    }

    $muxRoutes = slb-GetMuxAdvertisedRoutes
    if($muxRoutes -eq $null) {
        WriteLog "!!! BUG BUG failed to get info using slb-GetMuxAdvertisedRoutes" $LogPath
    }
    else {
	$Routes = $muxRoutes.MuxAdvertisedRoutes
     	$RouteCount = $Routes.Count
        WriteLog ("MuxAdvertisedRoutes count is : $RouteCount") $LogPath	
        foreach($Route in  $Routes){
        	$Route >> $LogPath
	}
    }
}
catch
{
    WriteLog $_ $LogPath
    WriteLog "!!! BUG BUG failed to get MUX Advertized RoutesInformation" $LogPath
}
WriteLog "####################### MUX Advertized Routes Ends #######################" $LogPath

WriteLog "####################### All Vip Informations Starts #######################" $LogPath
try
{
    $vips = slb-GetAllVipsGS
    if($vips -eq $null) {
        WriteLog "!!! BUG BUG failed to get info using slb-GetAllVipsGS" $LogPath
    }
    else {
        $vips >> $LogPath
    }

    $vipRange = slb-GetVipRanges
    if($vipRange -eq $null) {
        WriteLog "!!! BUG BUG failed to get info using slb-GetVipRanges" $LogPath
    }
    else {
        WriteLog "Configured VIP Ranges" $LogPath
        $vipRange >> $LogPath
    }

    foreach($key in $vips.keys)
    {
        $Vip = $key.IPAddressToString
        WriteLog "Vip is :$Vip" $LogPath
    
        try
        {
            $VipState = slb-GetVipState-Raw -vip:$Vip
            if($VipState -eq $null) {
                WriteLog "!!! BUG BUG failed to get info using slb-GetVipState" $LogPath
            }
            else {
                $VipEndPoints = $VipState.VipEndpointStates
		$VipEndPointsCount = $VipEndPoints.Count
		WriteLog "Vip EndPoints count is: $VipEndPointsCount" $LogPath
		foreach($VipEndPoint in $VipEndPoints) {
		    $VipEP = $VipEndPoint.VipEndPoint
                    $VipEPStatus = $VipEndPoint.CurrentStatus
                    WriteLog "  Vip EndPoint is: $VipEP, Status : $VipEPStatus" $LogPath
                    $DipEndPoints = $VipEndPoint.DipEndPoints
		    $DipEndPointsCount = $DipEndPoints.Count
		    WriteLog "    Dip EndPoints count is: $DipEndPointsCount" $LogPath
		    foreach($DipEndPoint in $DipEndPoints.Values) {
                        $DipEP = $DipEndPoint.DipEndpoint
                        $DipEPStatus = $DipEndPoint.GoalState
                        $DipEPHealthStatus = $DipEndPoint.DipMonitoredState
                        WriteLog "      Dip EndPoint is: $DipEP" $LogPath                    
                        WriteLog "      Dip EndPoint Status is: $DipEPStatus" $LogPath
                        WriteLog "      Dip EndPoint Health is: $DipEPHealthStatus" $LogPath
                    }
		}
            }
        }
        catch
        {
            WriteLog $_ $LogPath
            WriteLog "!!! BUG BUG failed to get state for vip:$Vip" $LogPath
        }
    }

    if($Details -eq $true)
    {
        foreach($key in $vips.keys)
        {
            $Vip = $key.IPAddressToString
            WriteOutput "Vip is :$Vip" $LogPath
    
            try
            {
                $VipState = slb-GetVipState -vip:$Vip -detail | fl
                if($VipState -eq $null) {
                    WriteOutput "!!! BUG BUG failed to get info using slb-GetVipState" $LogPath
                }
                else {
                    $VipState >> $LogPath
                }
            }    
            catch
            {
                WriteOutput $_ $LogPath
                WriteOutput "!!! BUG BUG failed to get state for vip:$Vip" $LogPath
            }
        }
    }
}
catch
{
    WriteLog $_ $LogPath
    WriteLog "!!! BUG BUG failed to get Vip Information" $LogPath
}
WriteLog "####################### All Vip Informations Ends #######################" $LogPath
cd $CurrentPath