# --------------------------------------------------------------
#  Copyright © Microsoft Corporation.  All Rights Reserved.
#  Microsoft Corporation (or based on where you live, one of its affiliates) licenses this sample code for your internal testing purposes only.
#  Microsoft provides the following sample code AS IS without warranty of any kind. The sample code arenot supported under any Microsoft standard support program or services.
#  Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#  The entire risk arising out of the use or performance of the sample code remains with you.
#  In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the code be liable for any damages whatsoever
#  (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
#  arising out of the use of or inability to use the sample code, even if Microsoft has been advised of the possibility of such damages.
# ---------------------------------------------------------------
[CmdletBinding(DefaultParameterSetName="NoParameters")]
param(
    [Parameter(Mandatory=$false)]
    [switch] $Undo
)

$VerbosePreference = "Continue"

$ConfigData = @{  
            
    # This contains the name of the server and share for the deployment infrastructure.  This must be shared with read/write for everyone.
    InstallSrcDir="\\$env:Computername\Deployment"

    TenantName="Contoso"              # VirtualGateway ResourceID
            
    # Network controller computer name with FQDN
    NetworkControllerRestIP = "SDNNCREST.$env:USERDNSDOMAIN"                                     # Must be FQDN for SSL
            
    # User credentials for communicating with the network controller.  Must contain domain.  Example:: Contoso\Greg
    NCUsername = 'SDNDC\administrator'
    NCPassword = 'Example'

    # HNV Control Virtual Network and Virtual Subnet GUID (Subnet to be used for HNV Control routing)
    #Virtual network information.  You don't need to change this, unless you want to.
    Network = @{
        GUID  = "2089e2a0-6c3b-43cf-8797-2cd47238beee"
        Subnets = @(
            @{
                Guid = "bf244e5e-31b4-42db-a59c-0ec9c7e2c7f4"
            }
        )
    }            

    # Tenant S2S Tunnel connections
    NetworkConnections = 
    @(
        @{
            # Tunnel name, will be used for Network Connection Resource Id as well
            TunnelName = "Contoso_IPSec"
            TunnelType = "IPSec"
            OutboundCapacity = "100000"
            InboundCapacity = "100000"

            # Post connect routes over the tunnel
            # The current /32 route is the Enterprise BGP Router's IP Address
            # You can also add multiple subnets here
            Routes = @(
                @{
                    Prefix = "14.1.10.1/32"
                    Metric = 10
                }
            )
            IPAddresses = @()
            PeerIPAddresses = @()

            # Tunnel Destination (Enterprise Gateway) IP Address
            DestinationIPAddress = "10.127.134.115"
            # Pre Shared Key (Only PSK is enabled via this script for IPSec VPN)
            SharedSecret = "111_aaa"                      
        },
        @{
            # Tunnel name, will be used for Network Connection Resource Id as well
            TunnelName = "Contoso_Gre"
            TunnelType = "Gre"
            OutboundCapacity = "100000"
            InboundCapacity = "100000"
                    
            # Post connect routes over the tunnel
            # The current /32 route is the Enterprise BGP Router's IP Address
            # You can also add multiple subnets here
            Routes = @(
                @{
                    Prefix = "14.1.20.1/32"
                    Metric = 10
                }
            )
            IPAddresses = @()
            PeerIPAddresses = @()
                    
            # Tunnel Destination (Enterprise Gateway) IP Address
            DestinationIPAddress = "10.127.134.120"
            # GRE Key for Tunnel Isolation 
            GreKey = "1234"                      
        },
        @{
            # Tunnel name, will be used for Network Connection Resource Id as well
            TunnelName = "Contoso_L3"
            TunnelType = "L3"
            OutboundCapacity = "100000"
            InboundCapacity = "100000"
                    
            # VLAN subnet network used for L3 forwarding
            Network = @{
                GUID = "Contoso_L3_Network"        
                Subnets = @(
                    @{
                    Guid = "Contoso_L3_Subnet1"
                    AddressSpace = "10.127.134.0"
                    Mask = 25
                    DefaultGateway = "10.127.134.1"
                    VlanId = 1001
                    }
                )
            }
            # Post connect routes over the tunnel
            # The current /32 route is the Enterprise BGP Router's IP Address
            # You can also add multiple subnets here
            Routes = @(
                @{
                    Prefix = "14.1.30.1/32"
                    Metric = 10
                }
            )
            # Local HNV Gateway's L3 Forwarding IP Address
            IPAddresses = @(
                @{
                    IPAddress = "10.127.134.50"
                    Mask = 25
                }
            )
            # Remote Gateway's L3 Forwarding IP Address
            PeerIPAddresses = @("10.127.134.60")
        }
    )

    GatewayPools = @("default")
    RoutingType = "Dynamic"

    BgpRouter = 
    @{
        RouterId = "Contoso_Vnet_Router1"
        LocalASN = 64510
        RouterIP = "192.168.0.2"
    }

    BgpPeers = 
    @(
        @{
                    PeerName = "Contoso_SiteA_IPSec"
                    PeerIP   = "14.1.10.1"
                    PeerASN  = 64521
                    },
        @{
                    PeerName = "Contoso_SiteB_Gre"
                    PeerIP   = "14.1.20.1"
                    PeerASN  = 64522
                    },
        @{
                    PeerName = "Contoso_SiteC_L3"
                    PeerIP   = "14.1.30.1"
                    PeerASN  = 64523
                    }
    )

<#
            ## For information on BGP Routing policy attributes, please refer to the TechNet Documentation (https://technet.microsoft.com/en-us/library/dn262662(v=wps.630).aspx) ##

    PolicyMaps = @(
        @{
            PolicyMapName = "IngressPolicyMap1"
            PolicyList = @(
                @{
                    PolicyName = "IngressPolicy1"
                    PolicyType = "Deny"
                    MatchCriteria = @(
                        @{
                            Clause = "MatchPrefix"
                            Value  = @("5.4.3.2/32", "5.4.3.1/32")
                        },
                        @{
                            Clause = "NextHop"
                            Value  = @("4.3.2.1", "6.4.3.1")
                        }
                    )
                    SetAction = @()
                }
            )
        },
        @{
            PolicyMapName = "EgressPolicyMap1"
            PolicyList = @(
                @{
                    PolicyName = "EgressPolicy1"
                    PolicyType = "Permit"
                    MatchCriteria = @(
                        @{
                            Clause = "IgnorePrefix"
                            Value  = @("3.3.3.3/32")
                        }
                    )
                    SetAction = @(
                        @{
                            Clause = "LocalPref"
                            Value  = @("123")
                        }
                    )
                }
            )
        }
    )
#>
  
}


. "$($configData.installsrcdir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $ConfigData.NetworkControllerRestIP -Username $ConfigData.NCUsername -Password $ConfigData.NCPassword

if ($undo.IsPresent -eq $false) 
{
    $networkConnectionInfo = $ConfigData.NetworkConnections
    $vNetInfo = $ConfigData.Network
<#
    $password =  convertto-securestring $ConfigData.NCPassword -asplaintext -force
    $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $ConfigData.NCUsername,$password
    set-ncconnection $ConfigData.NetworkControllerRestIP -Credential $credential
    #>
    $TenantName = $ConfigData.TenantName

    $virtualGateway = @{}
    $virtualGatewayId = $TenantName

    # Get the first virtual Network control subnet to use it with the Virtual Gateway Rest Object
    $ipv4SubnetResourceRef = "/virtualNetworks/$($vNetInfo.GUID)/subnets/$($vNetInfo.Subnets[0].Guid)"

    # Get the VPN Client Address space info
    $vpnClientAddressPool = $null
    $vpnClientInfo = $ConfigData.P2SVpn

    if($vpnClientInfo -ne $null)
    {
        $vpnClientAddressPool = New-VpnClientAddressSpace -TenantName $TenantName -VpnCapacity $vpnClientInfo.Capacity -Ipv4AddressPool $vpnClientInfo.IPv4AddressPool -Ipv6AddressPool $vpnClientInfo.IPv6AddressPool
    }

    $RoutingType = $ConfigData.RoutingType

    $policyMaps = @()
    $bgpRouters = @()
    $bgpPeers = @()

    if ($RoutingType -eq "Dynamic")
    {
        # Get the Routing Policy Map Json
        foreach ($policyMap in $ConfigData.PolicyMaps)
        {
            $policyObj = @()
            foreach ($policy in $policyMap.PolicyList)
            {
                $policyObj += (New-BgpRoutingPolicy -PolicyName $policy.PolicyName -PolicyType $policy.PolicyType -MatchCriteriaList $policy.MatchCriteria -Actions $policy.SetAction)
            }
            $policyMaps += (New-BgpRoutingPolicyMap -PolicyMapName $policyMap.PolicyMapName -PolicyList $policyObj)
        }        

        # Get the BgpPeer Json
        $inMap = $null
        $outMap = $null

        foreach ($bgpPeer in $ConfigData.BgpPeers)
        {
            # using First PolicyMap as Inbound and 2nd as outbound
            if ($policyMaps.count -eq 2)
            {
                $inMapResourceRef = "/VirtualGateways/$virtualGatewayId/PolicyMaps/$($policyMaps[0].ResourceId)"
                $outMapResourceRef = "/VirtualGateways/$virtualGatewayId/PolicyMaps/$($policyMaps[1].ResourceId)"
            }
            else
            {
                $inMapResourceRef = $null
                $outMapResourceRef = $null
            }

            $bgpPeers += (New-BgpPeer -PeerName $bgpPeer.PeerName -PeerIP $bgpPeer.PeerIP -PeerASN $bgpPeer.PeerASN.ToString() -IngressPolicyMapResourceRef $inMapResourceRef -EgressPolicyMapResourceRef $outMapResourceRef)
        }

        $bgpRouter = (New-BgpRouter -RouterName $ConfigData.BgpRouter.RouterId -LocalASN $ConfigData.BgpRouter.LocalASN.ToString() -BgpPeers $bgpPeers)
        $bgpRouters += $bgpRouter
    }


    # Get the network connections
    $nwConnections = @()

    foreach ($connection in $networkConnectionInfo)
    {
        switch ($connection.TunnelType)
        {
            "IPSec" {
                    $nwConnections += (New-IPSecTunnel -ResourceId $connection.TunnelName -OutboundCapacity $connection.OutboundCapacity -InboundCapacity $connection.InboundCapacity `
                                                        -DestinationIPAddress $connection.DestinationIPAddress -SharedSecret $connection.SharedSecret -IPv4Subnets $connection.Routes )
                    break
                }
            "GRE" {
                    $nwConnections += (New-GreTunnel -ResourceId $connection.TunnelName -OutboundCapacity $connection.OutboundCapacity -InboundCapacity $connection.InboundCapacity `
                                                        -DestinationIPAddress $connection.DestinationIPAddress -GreKey $connection.GreKey -IPv4Subnets $connection.Routes )
                    break
                }
            "L3" {
                    # Post a Logical network subnet for L3 Tunnel
                    $ipAddresses = @()

                    $l3Network = $connection.Network
                    $l3Subnets = $connection.Network.Subnets
                    $l3IPAddresses = $connection.IPAddresses

                    $subnet = @()
                    if ($l3Subnets -ne $null -and $l3Subnets.count -gt 0)
                    {
                        foreach ($l3Subnet in $l3Subnets)
                        {
                            $subnet += New-NCLogicalNetworkSubnet -ResourceID $l3Subnet.Guid -AddressPrefix "$($l3Subnet.AddressSpace)/$($l3Subnet.Mask)" -defaultGateway $l3Subnet.DefaultGateway -VLANid $l3Subnet.VlanId 
                        }
                        $logicalNetwork = New-NCLogicalNetwork -ResourceID $connection.Network.GUID -LogicalNetworkSubnets @($subnet)
                    }
                    elseif ($l3Network -ne $null)
                    {
                        $logicalNetwork = Get-NCLogicalNetwork -ResourceID $l3Network.ResourceId
                    }

                    foreach ($l3IP in $l3IPAddresses)
                    {
                        $obj = @{}
                        $obj.ipAddress = $l3IP.IPAddress
                        $obj.prefixLength = $l3IP.Mask
                        $ipAddresses += $obj
                    }

                    if ($logicalNetwork -ne $null)
                    {
                        $vlanSubnetResourceRef = $logicalNetwork.properties.subnets[0].resourceRef
                
                        if (![string]::IsNullOrEmpty($vlanSubnetResourceRef))
                        {
                            $nwConnections += (New-L3Tunnel -ResourceId $connection.TunnelName -OutboundCapacity $connection.OutboundCapacity -InboundCapacity $connection.InboundCapacity `
                                                            -VlanSubnetResourceRef $vlanSubnetResourceRef -L3IPAddresses $ipAddresses -PrefixLength $connection.PrefixLength `
                                                            -L3PeerIPAddresses @($connection.PeerIPAddresses) -IPv4Subnets $connection.Routes)
                        }
                    }
                    break
                }
        }      
    }

    $invalidGwPoolCombination = $false

    if ($ConfigData.GatewayPools.count -gt 1)
    {
        # check if the GW Pools violate the condition of "mutually exclusive types"
        $gwPoolTypes = @()

        foreach ($gwPool in $ConfigData.GatewayPools)
        {
            $GatewayPoolObj = Get-NCGatewayPool -ResourceId $gwPool
            if ($GatewayPoolObj.properties.type -eq "All" -or $gwPoolTypes.Contains($GatewayPoolObj.properties.type))
            {
                $invalidGwPoolCombination = $true
                break
            }
            else
            {
                $gwPoolTypes += $GatewayPoolObj.properties.type
                $gwPoolTypes = $gwPoolTypes | sort -Unique
            }
        }

        if ($gwPoolTypes.count -ne $ConfigData.GatewayPools.count -or $invalidGwPoolCombination)
        {
            Write-Warning "Invalid Gateway Pool combinations specified. Gateway Pool can either be 'All', or a set of mutually exclusive individual types (maximum one each from 'S2sIpSec', 'Gre' or 'Forwarding')"
            return 
        }

    }

    $result = New-VirtualGateway -resourceID $virtualGatewayId -GatewayPools $ConfigData.GatewayPools -vNetIPv4SubnetResourceRef $ipv4SubnetResourceRef `
                                            -VpnClientAddressSpace $vpnClientAddressPool -NetworkConnections $nwConnections -BgpRouters $bgpRouters -PolicyMaps $policyMaps -RoutingType $RoutingType

    $virtualGateway = Get-VirtualGateway -ResourceID $virtualGatewayId

    if ($virtualGateway -ne $null)
    {
        Write-Host "`n`n>>>>> Please use the following VPN configuration for the enterprise Gateways <<<<<" -ForegroundColor Green
        foreach ($nc in $virtualGateway.properties.networkConnections)
        {
            Write-Host "    Network Connection Id - $($nc.resourceId)"`
                       "`n                       Type - $($nc.properties.connectionType)"
            switch ($nc.properties.connectionType)
            {
                "IPSec" {
                    $pubIP = JSONGet -NetworkControllerRestIP $script:NetworkControllerRestIP -path $nc.properties.sourceIPAddress.resourceRef -WaitForUpdate -credential $script:NetworkControllerCred

                    Write-Host "                       Cloud IP Address - $($pubIP.properties.ipAddress)`n"
                }
                "GRE" {
                    Write-Host "                       Cloud IP Address - $($nc.properties.internalSourceIPAddress)`n"
                }
                "L3" {
                    foreach ($ipAdd in $nc.properties.ipAddresses)
                    {
                        Write-Host "                       Cloud IP Address - $($ipAdd.ipAddress)"
                    }
                }
            }
        }
        Write-Host "`n>>>>> Please use the following BGP configuration for the enterprise Sites <<<<<" -ForegroundColor Green
        foreach ($router in $virtualGateway.properties.bgpRouters)
        {
            Write-Host "    Cloud BGP Router's IP Address - $($router.properties.routerIP)"`
                       "`n    Cloud BGP Router's AS Number  - $($router.properties.extASNumber)"
        }
        Write-Host "`n`n"
    }

}
else # Perform Undo
{
    $node = $ConfigData
    . "$($node.InstallSrcDir)\scripts\NetworkControllerRESTWrappers.ps1" -ComputerName $node.NetworkControllerRestIP -UserName $node.ncUsername -Password $node.ncpassword

    $password =  convertto-securestring $ConfigData.NCPassword -asplaintext -force
    $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $ConfigData.NCUsername,$password
    set-ncconnection $ConfigData.NetworkControllerRestIP -Credential $credential
    
    $virtualGatewayId = $ConfigData.TenantName

    # Remove Virtual Gateway
    Remove-VirtualGateway -resourceID $virtualGatewayId 
}