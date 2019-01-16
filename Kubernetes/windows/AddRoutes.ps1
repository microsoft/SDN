Param(
    [parameter(Mandatory = $true)] [string] $masterIp
)

function
Add-RouteToPodCIDR($nicName, $routeMetric = 300)
{
    while (!$podCIDRs) {
        Start-Sleep 5
        $podCIDRs=Get-PodCIDRs
        Write-Host "Add-RouteToPodCIDR - available nodes $podCIDRs"
    }

    foreach ($podcidr in $podCIDRs)
    {
        $tmp = $podcidr.Split(" ")
        $os = $tmp | select -First 1
        $cidr = $tmp | select -Last 1
        $cidrGw =  $cidr.substring(0,$cidr.lastIndexOf(".")) + ".1"

        if ($os -eq "windows") {
            $cidrGw = $cidr.substring(0,$cidr.lastIndexOf(".")) + ".2"
        }

        Write-Host "Adding route for Remote Pod CIDR $cidr, GW $cidrGw, for node type $os"

        $route = get-netroute -InterfaceAlias "$nicName" -DestinationPrefix $cidr -erroraction Ignore
        if (!$route) {
            new-netroute -InterfaceAlias "$nicName" -DestinationPrefix $cidr -NextHop  $cidrGw -RouteMetric $routeMetric -Verbose
        }
    }
}

$endpointName = "cbr0"
$vnicName = "vEthernet ($endpointName)"
$WorkingDir = "c:\k"

ipmo $WorkingDir\helper.psm1

# Add routes to all POD networks on the Bridge endpoint nic
Add-RouteToPodCIDR -nicName $vnicName -RouteMetric 250

$na = Get-NetAdapter | ? Name -Like "vEthernet (Ethernet*" | ? Status -EQ Up
if (!$na)
{
    Write-Error "Do you have a virtual adapter configured? Couldn't find one!"
    exit 1
}

# Add routes to all POD networks on the Mgmt Nic on the host
Add-RouteToPodCIDR -nicName $na.InterfaceAlias -RouteMetric 300

# Update the route for the POD on current host to be on Link
$podCIDR=Get-PodCIDR
get-NetRoute -DestinationPrefix $podCIDR  -InterfaceAlias $na.InterfaceAlias | Remove-NetRoute -Confirm:$false
new-NetRoute -DestinationPrefix $podCIDR -NextHop 0.0.0.0 -InterfaceAlias $na.InterfaceAlias -RouteMetric 300

# Add a route to Master, to override the Remote Endpoint
$route = Get-NetRoute -DestinationPrefix "$masterIp/32" -erroraction Ignore
if (!$route)
{
    $gateway = Get-MgmtDefaultGatewayAddress
    Write-Host "Adding a route for $masterIp with NextHop $gateway"
    New-NetRoute -DestinationPrefix "$masterIp/32" -NextHop $gateway  -InterfaceAlias $na.InterfaceAlias -Verbose
}
