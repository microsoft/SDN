#########################################################################
# Global Initialize
function Get-VmComputeNativeMethods()
{
        $signature = @'
                     [DllImport("vmcompute.dll")]
                     public static extern void HNSCall([MarshalAs(UnmanagedType.LPWStr)] string method, [MarshalAs(UnmanagedType.LPWStr)] string path, [MarshalAs(UnmanagedType.LPWStr)] string request, [MarshalAs(UnmanagedType.LPWStr)] out string response);
'@

    # Compile into runtime type
    Add-Type -MemberDefinition $signature -Namespace VmCompute.PrivatePInvoke -Name NativeMethods -PassThru
}

#########################################################################
# Configuration
#########################################################################
function Get-HnsSwitchExtensions
{
    param
    (
        [parameter(Mandatory=$true)] [string] $NetworkId
    )

    return (Get-HNSNetwork $NetworkId).Extensions
}

function Set-HnsSwitchExtension
{
    param
    (
        [parameter(Mandatory=$true)] [string] $NetworkId,
        [parameter(Mandatory=$true)] [string] $ExtensionId,
        [parameter(Mandatory=$true)] [bool]   $state
    )

    # { "Extensions": [ { "Id": "...", "IsEnabled": true|false } ] }
    $req = @{
        "Extensions"=@(@{
            "Id"=$ExtensionId;
            "IsEnabled"=$state;
        };)
    }
    Invoke-HNSRequest -Method POST -Type networks -Id $NetworkId -Data (ConvertTo-Json $req)
}

#########################################################################
# Activities
#########################################################################
function Get-HNSActivities
{
    [cmdletbinding()]Param()
    return Invoke-HNSRequest -Type activities -Method GET
}

#########################################################################
# PolicyLists
#########################################################################
function Get-HNSPolicyLists {
    [cmdletbinding()]Param()
    return Invoke-HNSRequest -Type policylists -Method GET
}

function Get-HnsPolicyList {
    param
    (
        [parameter(Mandatory = $true)] [string] $Id
    )

    return Invoke-HNSRequest -Method GET -Type policylists -Id $id
}
function Remove-HnsPolicyList
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [Object[]] $InputObjects
    )
    begin {$Objects = @()}
    process {$Objects += $InputObjects; }
    end {
        $Objects | foreach {  Invoke-HNSRequest -Method DELETE -Type  policylists -Id $_.Id }
    }
}

function New-HnsRoute {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $true)] [string] $DestinationPrefix,
        [parameter(Mandatory = $false)] [switch] $EncapEnabled
    )

    $policyLists = @{
        References = @(
            get-endpointReferences $Endpoints;
        );
        Policies   = @(
            @{
                Type = "ROUTE";
                DestinationPrefix = $DestinationPrefix;
                NeedEncap = $EncapEnabled.IsPresent;
            }
        );
    }

    Invoke-HNSRequest -Method POST -Type policylists -Data (ConvertTo-Json  $policyLists -Depth 10)
}

function New-HnsLoadBalancer {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $true)] [int] $InternalPort,
        [parameter(Mandatory = $true)] [int] $ExternalPort,
        [parameter(Mandatory = $false)] [string] $Vip
    )

    $policyLists = @{
        References = @(
            get-endpointReferences $Endpoints;
        );
        Policies   = @(
            @{
                Type = "ELB";
                InternalPort = $InternalPort;
                ExternalPort = $ExternalPort;
                VIPs = @($Vip);
            }
        );
    }

    Invoke-HNSRequest -Method POST -Type policylists -Data ( ConvertTo-Json  $policyLists -Depth 10)
}


function get-endpointReferences {
    param
    (
        [parameter(Mandatory = $true)] [Guid[]] $Endpoints = $null
    )
    if ($Endpoints ) {
        $endpointReference = @()
        foreach ($endpoint in $Endpoints)
        {
            $endpointReference += "/endpoints/$endpoint"
        }
        return $endpointReference
    }
    return @()
}

#########################################################################
# Networks
#########################################################################

function Get-HNSNetwork
{
    param
    (
        [parameter(Mandatory=$true)] [string] $Id
    )

    return Invoke-HNSRequest -Method GET -Type networks -Id $id
}

function Get-HNSNetworks
{
    [cmdletbinding()]Param()
    return Invoke-HNSRequest -Type networks -Method GET
}

function Remove-HNSNetwork
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [Object[]] $InputObjects
    )
    begin {$Objects = @()}
    process {$Objects += $InputObjects; }
    end {
        $Objects | foreach {  Invoke-HNSRequest -Method DELETE -Type  networks -Id $_.Id }
    }
}

function New-HnsNetwork
{
    param
    (
        [parameter(Mandatory=$false, Position=0)]
        [string] $JsonString,
        [ValidateSet('ICS', 'Internal', 'Transparent', 'NAT', 'Overlay', 'L2Bridge', 'L2Tunnel', 'Layered', 'Private')]
        [parameter(Mandatory = $false, Position = 0)]
        [string] $Type,
        [parameter(Mandatory = $false)] [string] $Name,
        [parameter(Mandatory = $false)] [string] $AddressPrefix,
        [parameter(Mandatory = $false)] [string] $Gateway,
        [parameter(Mandatory = $false)] [string] $DNSServer,
        [parameter(Mandatory = $false)] [string] $AdapterName
    )

    Begin {
        if (!$JsonString) {
            $netobj = @{
                Type          = $Type;
            };

            if ($Name) {
                $netobj += @{
                    Name = $Name;
                }
            }

            if ($AddressPrefix -and  $Gateway) {
                $netobj += @{
                    Subnets = @(
                        @{
                            AddressPrefix  = $AddressPrefix;
                            GatewayAddress = $Gateway;
                        }
                    );
                }
            }

            if ($DNSServerName) {
                $netobj += @{
                    DNSServerList = $DNSServer
                }
            }

            if ($AdapterName) {
                $netobj += @{
                    NetworkAdapterName = $AdapterName;
                }
            }

            $JsonString = ConvertTo-Json $netobj -Depth 10
        }

    }
    Process{
        return Invoke-HNSRequest -Method POST -Type networks -Data $JsonString
    }
}

#########################################################################
# Endpoints
#########################################################################

#########################################################################

# Get-HNSEndpointById
<#
    .Synopsis

    .Description

    .Parameter Type

#>

function Get-HNSEndpoint
{
    param
    (
        [parameter(Mandatory=$true)] [string] $Id
    )

    return Invoke-HNSRequest -Method GET -Type endpoints -Id $id
}


#########################################################################

# Get-HNSEndpoints
<#
    .Synopsis
    Get All HNS Endpoint Objects

    .Description

    .Parameter Type

#>

function Get-HnsEndpoints
{
    [cmdletbinding()]Param()
    return  Invoke-HNSRequest -Type endpoints -Method GET
}

function Remove-HNSEndpoint
{
    param
    (
        [parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)]
        [Object[]] $InputObjects
    )

    begin {$objects = @()}
    process {$Objects += $InputObjects; }
    end {
        $Objects | foreach {  Invoke-HNSRequest -Method DELETE -Type endpoints -Id $_.Id  }
    }
}

function New-HnsEndpoint
{
    param
    (
        [parameter(Mandatory=$false, Position = 0)] [string] $JsonString = $null,
        [parameter(Mandatory = $false, Position = 0)] [Guid] $NetworkId,
        [parameter(Mandatory = $false)] [string] $Name,
        [parameter(Mandatory = $false)] [string] $IPAddress,
        [parameter(Mandatory = $false)] [string] $Gateway,
        [parameter(Mandatory = $false)] [string] $MacAddress,
        [parameter(Mandatory = $false)] [switch] $EnableOutboundNat
    )

    begin
    {
        if ($JsonString)
        {
            $EndpointData = $JsonString | ConvertTo-Json | ConvertFrom-Json
        }
        else
        {
            $endpoint = @{
                VirtualNetwork = $NetworkId;
                Policies       = @();
            }

            if ($Name) {
                $endpoint += @{
                    Name = $Name;
                }
            }

            if ($MacAddress) {
                $endpoint += @{
                    MacAddress     = $MacAddress;
                }
            }

            if ($IPAddress) {
                $endpoint += @{
                    IPAddress      = $IPAddress;
                }
            }

            if ($Gateway) {
                $endpoint += @{
                    GatewayAddress = $Gateway;
                }
            }

            if ($EnableOutboundNat) {
                $endpoint.Policies += @{
                    Type = "OutBoundNAT";
                }

            }
            # Try to Generate the data
            $EndpointData = convertto-json $endpoint
        }
    }

    Process
    {
        return Invoke-HNSRequest -Method POST -Type endpoints -Data $EndpointData
    }
}


function New-HnsRemoteEndpoint
{
    param
    (
        [parameter(Mandatory = $true)] [Guid] $NetworkId,
        [parameter(Mandatory = $false)] [string] $IPAddress,
        [parameter(Mandatory = $false)] [string] $MacAddress
    )

    $remoteEndpoint = @{
        ID = [Guid]::NewGuid();
        VirtualNetwork = $NetworkId;
        IPAddress = $IPAddress;
        MacAddress = $MacAddress;
        IsRemoteEndpoint = $true;
    }

    return Invoke-HNSRequest -Method POST -Type endpoints -Data (ConvertTo-Json $remoteEndpoint  -Depth 10)

}


function Attach-HnsHostEndpoint
{
    param
    (
     [parameter(Mandatory=$true)] [Guid] $EndpointID,
     [parameter(Mandatory=$true)] [int] $CompartmentID
     )
    $request = @{
        SystemType    = "Host";
        CompartmentId = $CompartmentID;
    };

    return Invoke-HNSRequest -Method POST -Type endpoints -Data (ConvertTo-Json $request) -Action "attach" -Id $EndpointID
}

function Attach-HNSVMEndpoint
{
    param
    (
     [parameter(Mandatory=$true)] [Guid] $EndpointID,
     [parameter(Mandatory=$true)] [string] $VMNetworkAdapterName
     )

    $request = @{
        VirtualNicName   = $VMNetworkAdapterName;
        SystemType    = "VirtualMachine";
    };
    return Invoke-HNSRequest -Method POST -Type endpoints -Data (ConvertTo-Json $request ) -Action "attach" -Id $EndpointID

}

function Attach-HNSEndpoint
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $EndpointID,
        [parameter(Mandatory=$true)] [int] $CompartmentID,
        [parameter(Mandatory=$true)] [string] $ContainerID
    )
     $request = @{
        ContainerId = $ContainerID;
        SystemType="Container";
        CompartmentId = $CompartmentID;
    };

    return Invoke-HNSRequest -Method POST -Type endpoints -Data (ConvertTo-Json $request) -Action "attach" -Id $EndpointID
}

function Detach-HNSVMEndpoint
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $EndpointID
    )
    $request = @{
        SystemType  = "VirtualMachine";
    };

    return Invoke-HNSRequest -Method POST -Type endpoints -Data (ConvertTo-Json $request ) -Action "detach" -Id $EndpointID
}

function Detach-HNSHostEndpoint
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $EndpointID
    )
    $request = @{
        SystemType  = "Host";
    };

    return Invoke-HNSRequest -Method POST -Type endpoints -Data (ConvertTo-Json $request ) -Action "detach" -Id $EndpointID
}

function Detach-HNSEndpoint
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $EndpointID,
        [parameter(Mandatory=$true)] [string] $ContainerID
    )

    $request = @{
        ContainerId = $ContainerID;
        SystemType="Container";
    };

    return Invoke-HNSRequest -Method POST -Type endpoints -Data (ConvertTo-Json $request ) -Action "detach" -Id $EndpointID
}
#########################################################################

function Invoke-HNSRequest
{
    param
    (
        [ValidateSet('GET', 'POST', 'DELETE')]
        [parameter(Mandatory=$true)] [string] $Method,
        [ValidateSet('networks', 'endpoints', 'activities', 'policylists', 'endpointstats', 'plugins')]
        [parameter(Mandatory=$true)] [string] $Type,
        [parameter(Mandatory=$false)] [string] $Action = $null,
        [parameter(Mandatory=$false)] [string] $Data = $null,
        [parameter(Mandatory=$false)] [Guid] $Id = [Guid]::Empty
    )

    $hnsPath = "/$Type"

    if ($id -ne [Guid]::Empty)
    {
        $hnsPath += "/$id";
    }

    if ($Action)
    {
        $hnsPath += "/$Action";
    }

    $request = "";
    if ($Data)
    {
        $request = $Data
    }

    $output = "";
    $response = "";
    Write-Verbose "Invoke-HNSRequest Method[$Method] Path[$hnsPath] Data[$request]"

    $hnsApi = Get-VmComputeNativeMethods
    $hnsApi::HNSCall($Method, $hnsPath, "$request", [ref] $response);

    Write-Verbose "Result : $response"
    if ($response)
    {
        try {
            $output = ($response | ConvertFrom-Json);
        } catch {
            Write-Error $_.Exception.Message
            return ""
        }
        if ($output.Error)
        {
             Write-Error $output;
        }
        $output = $output.Output;
    }

    return $output;
}

#########################################################################

Export-ModuleMember -Function Get-HNSActivities
Export-ModuleMember -Function Get-HnsSwitchExtensions
Export-ModuleMember -Function Set-HnsSwitchExtension

Export-ModuleMember -Function Get-HNSNetworks
Export-ModuleMember -Function Get-HNSNetwork
Export-ModuleMember -Function Remove-HNSNetwork
Export-ModuleMember -Function New-HNSNetwork

Export-ModuleMember -Function Get-HNSEndpoint
Export-ModuleMember -Function Get-HNSEndpoints
Export-ModuleMember -Function Remove-HNSEndpoint
Export-ModuleMember -Function New-HNSEndpoint
Export-ModuleMember -Function New-HnsRemoteEndpoint

Export-ModuleMember -Function Attach-HNSHostEndpoint
Export-ModuleMember -Function Attach-HNSVMEndpoint
Export-ModuleMember -Function Attach-HNSEndpoint
Export-ModuleMember -Function Detach-HNSHostEndpoint
Export-ModuleMember -Function Detach-HNSVMEndpoint
Export-ModuleMember -Function Detach-HNSEndpoint

Export-ModuleMember -Function Get-HNSPolicyLists
Export-ModuleMember -Function Get-HNSPolicyList
Export-ModuleMember -Function Remove-HnsPolicyList
Export-ModuleMember -Function New-HnsRoute
Export-ModuleMember -Function New-HnsLoadBalancer

Export-ModuleMember -Function Invoke-HNSRequest
