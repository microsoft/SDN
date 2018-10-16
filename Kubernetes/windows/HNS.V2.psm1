#########################################################################
# Global Initialize

function Get-HnsClientNativeMethods()
{
        $signature = @'
        // Networks

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnEnumerateNetworks(
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Networks,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCreateNetwork(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr Network,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnOpenNetwork(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr Network,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnModifyNetwork(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Network,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnQueryNetworkProperties(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Network,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Properties,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnDeleteNetwork(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCloseNetwork(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Network);

        // Namespaces

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnEnumerateNamespaces(
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Namespaces,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCreateNamespace(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr Namespace,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnOpenNamespace(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr Namespace,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnModifyNamespace(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Namespace,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnQueryNamespaceProperties(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Namespace,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Properties,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnDeleteNamespace(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCloseNamespace(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Namespace);

        // Endpoint

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnEnumerateEndpoints(
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Endpoints,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCreateEndpoint(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Network,
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr Endpoint,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnOpenEndpoint(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr Endpoint,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnModifyEndpoint(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Endpoint,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnQueryEndpointProperties(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Endpoint,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Properties,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnDeleteEndpoint(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCloseEndpoint(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Endpoint);

        // LoadBalancer

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnEnumerateLoadBalancers(
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string LoadBalancers,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCreateLoadBalancer(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr LoadBalancer,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnOpenLoadBalancer(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr LoadBalancer,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnModifyLoadBalancer(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr LoadBalancer,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnQueryLoadBalancerProperties(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr LoadBalancer,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Properties,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnDeleteLoadBalancer(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCloseLoadBalancer(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr LoadBalancer);

        // Service

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnOpenService(
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr Service,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnRegisterServiceCallback(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Service,
            [MarshalAs(UnmanagedType.I4)]
            System.Int32 Callback,
            [MarshalAs(UnmanagedType.I4)]
            System.Int32 Context,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr CallbackHandle);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnUnregisterServiceCallback(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr CallbackHandle);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCloseService(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Service);

        // Guest Network Service
        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnEnumerateGuestNetworkServices(
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string GuestNetworkServices,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCreateGuestNetworkService(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr GuestNetworkService,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnOpenGuestNetworkService(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr GuestNetworkService,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnModifyGuestNetworkService(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr GuestNetworkService,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnQueryGuestNetworkServiceProperties(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr GuestNetworkService,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Properties,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnDeleteGuestNetworkService(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);

        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCloseGuestNetworkService(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr GuestNetworkService);

'@

    # Compile into runtime type
    Add-Type -MemberDefinition $signature -Namespace ComputeNetwork.HNS.PrivatePInvoke -Name NativeMethods -PassThru
}


Add-Type -TypeDefinition @"
    public enum ModifyRequestType
    {
        Add,
        Remove,
        Update,
        Refresh
    };

    public enum EndpointResourceType
    {
        Port,
        Policy,
    };
    public enum NetworkResourceType
    {
        DNS,
        Extension,
    };
    public enum NamespaceResourceType
    {
    Container,
    Endpoint,
    };
"@

$ClientNativeMethods = Get-HnsClientNativeMethods

$NetworkNativeMethods = @{
    Open = $ClientNativeMethods::HcnOpenNetwork;
    Close = $ClientNativeMethods::HcnCloseNetwork;
    Enumerate = $ClientNativeMethods::HcnEnumerateNetworks;
    Delete = $ClientNativeMethods::HcnDeleteNetwork;
    Query = $ClientNativeMethods::HcnQueryNetworkProperties;
    Modify = $ClientNativeMethods::HcnModifyNetwork;
}

$EndpointNativeMethods = @{
    Open = $ClientNativeMethods::HcnOpenEndpoint;
    Close = $ClientNativeMethods::HcnCloseEndpoint;
    Enumerate = $ClientNativeMethods::HcnEnumerateEndpoints;
    Delete = $ClientNativeMethods::HcnDeleteEndpoint;
    Query = $ClientNativeMethods::HcnQueryEndpointProperties;
    Modify = $ClientNativeMethods::HcnModifyEndpoint;
}

$NamespaceNativeMethods = @{
    Open = $ClientNativeMethods::HcnOpenNamespace;
    Close = $ClientNativeMethods::HcnCloseNamespace;
    Enumerate = $ClientNativeMethods::HcnEnumerateNamespaces;
    Delete = $ClientNativeMethods::HcnDeleteNamespace;
    Query = $ClientNativeMethods::HcnQueryNamespaceProperties;
    Modify = $ClientNativeMethods::HcnModifyNamespace;
}

$LoadBalancerNativeMethods = @{
    Open = $ClientNativeMethods::HcnOpenLoadBalancer;
    Close = $ClientNativeMethods::HcnCloseLoadBalancer;
    Enumerate = $ClientNativeMethods::HcnEnumerateLoadBalancers;
    Delete = $ClientNativeMethods::HcnDeleteLoadBalancer;
    Query = $ClientNativeMethods::HcnQueryLoadBalancerProperties;
    Modify = $ClientNativeMethods::HcnModifyLoadBalancer;
}

$GuestNetworkServiceNativeMethods = @{
    Open = $ClientNativeMethods::HcnOpenGuestNetworkService;
    Close = $ClientNativeMethods::HcnCloseGuestNetworkService;
    Enumerate = $ClientNativeMethods::HcnEnumerateGuestNetworkServices;
    Delete = $ClientNativeMethods::HcnDeleteGuestNetworkService;
    Query = $ClientNativeMethods::HcnQueryGuestNetworkServiceProperties;
    Modify = $ClientNativeMethods::HcnModifyGuestNetworkService;
}

#########################################################################
# Generic implementation
#########################################################################

function Get-HnsGeneric
{
    param
    (
        [parameter(Mandatory=$false)] [Guid] $Id = [Guid]::Empty,
        [parameter(Mandatory=$false)] [Hashtable] $Filter = @{},
        [parameter(Mandatory=$false)] [Hashtable] $NativeMethods,
        [parameter(Mandatory=$false)] [switch]    $Detailed,
        [parameter(Mandatory=$false)] [int]       $Version
    )
    
    $ids = ""
    $FilterString = ConvertTo-Json $Filter -depth 10
    $query = @{Filter = $FilterString }
    if($Version -eq 2)
    {
        $query += @{SchemaVersion = @{ Major = 2; Minor = 0 }}
    }
    else
    {
        $query += @{SchemaVersion = @{ Major = 1; Minor = 0 }}
    }
    if($Detailed.IsPresent)
    {
        $query += @{Flags = 1}
    }
    $query = ConvertTo-Json $query
    if ($Id -ne [Guid]::Empty)
    {
        $ids = $Id
    }
    else
    {
        $result = ""
        $hr = $NativeMethods["Enumerate"].Invoke($query, [ref] $ids, [ref] $result);
        ReportErrors -FunctionName $NativeMethods["Enumerate"].Name -Hr $hr -Result $result -ThrowOnFail

        if($ids -eq $null)
        {
            return
        }

        $ids = ($ids | ConvertFrom-Json)
    }
    
    $output = @()
    $ids | ForEach-Object {
        $handle = 0
        $result = ""
        $hr = $NativeMethods["Open"].Invoke($_, [ref] $handle, [ref] $result);
        ReportErrors -FunctionName $NativeMethods["Open"].Name -Hr $hr -Result $result
        $properties = "";
        $result = ""
        $hr = $NativeMethods["Query"].Invoke($handle, $query, [ref] $properties, [ref] $result);
        ReportErrors -FunctionName $NativeMethods["Query"].Name -Hr $hr -Result $result
        $output += ConvertResponseFromJson -JsonInput $properties
        $hr = $NativeMethods["Close"].Invoke($handle);
        ReportErrors -FunctionName $NativeMethods["Close"].Name -Hr $hr
    }

    return $output
}

function Remove-HnsGeneric
{
    param
    (
        [parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)]
        [Object[]] $InputObjects,
        [parameter(Mandatory=$false)] [Hashtable] $NativeMethods
    )

    begin {$objects = @()}
    process
    {
        if($InputObjects)
        {
            $Objects += $InputObjects;
        }
    }
    end {
        $Objects | Foreach-Object {
            $result = ""
            $hr = $NativeMethods["Delete"].Invoke($_.Id, [ref] $result);
            ReportErrors -FunctionName $NativeMethods["Delete"].Name -Hr $hr -Result $result
        }
    }
    
}

function Modify-HnsGeneric
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$false)] [Hashtable] $NativeMethods,
        [HashTable][parameter(Mandatory=$false)] $Settings
    )

    $result = ""
    # Get endpoint handle
    $handle = 0
    $hr = $NativeMethods["Open"].Invoke($Id, [ref] $handle, [ref] $result);
    ReportErrors -FunctionName $NativeMethods["Open"].Name -Hr $hr -Result $result
    try {
        $jsonString = (ConvertTo-Json  $Settings -Depth 10)
        Write-Verbose $jsonString
        $hr = $NativeMethods["Modify"].Invoke($handle, $jsonString, [ref] $result);
        ReportErrors -FunctionName $NativeMethods["Modify"].Name -Hr $hr -Result $result

    } finally {
        $hr = $NativeMethods["Close"].Invoke($handle);
        ReportErrors -FunctionName $NativeMethods["Close"].Name -Hr $hr
    }
}

#########################################################################
# Namespaces
#########################################################################
function New-HnsNamespace {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $false)] [switch] $Default
    )
    $namespace=@{IsDefault=[bool]$Default; SchemaVersion = @{
                "Minor" = 2
                "Major" = 2
        }}

    $id = [Guid]::Empty
    $settings = (ConvertTo-Json  $namespace -Depth 10)
    $handle = 0
    $result = ""
    $hnsClientApi = Get-HnsClientNativeMethods
    $hr = $hnsClientApi::HcnCreateNamespace($id, $settings, [ref] $handle, [ref] $result);
    ReportErrors -FunctionName HcnCreateNamespace -Hr $hr -Result $result -ThrowOnFail

    $query = '{"SchemaVersion": { "Major": 1, "Minor": 0 }}'
    $properties = "";
    $result = ""
    $hr = $hnsClientApi::HcnQueryNamespaceProperties($handle, $query, [ref] $properties, [ref] $result);
    ReportErrors -FunctionName HcnQueryNamespaceProperties -Hr $hr -Result $result
    $hr = $hnsClientApi::HcnCloseNamespace($handle);
    ReportErrors -FunctionName HcnCloseNamespace -Hr $hr

    $output = ConvertResponseFromJson -JsonInput $properties

    if($Endpoints -ne $null)
    {
        Foreach ($endpoint in $endpoints)
        {
            $Settings = @{EndpointId = $endpoint}
            $requestType = [ModifyRequestType]::Add
            $resourceType = [NamespaceResourceType]::Endpoint
            Modify-HnsNamespace -ID $output.Id -Settings $Settings -RequestType $requestType -ResourceType $resourceType 
        }
    }

    return $output
}

function Get-HnsNamespace
{
    param
    (
        [parameter(Mandatory=$false)] [Guid] $Id = [Guid]::Empty,
        [parameter(Mandatory=$false)] [int] $Version,
        [parameter(Mandatory=$false)] [switch] $Detailed
    )
    if ( $Detailed.IsPresent)
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $NamespaceNativeMethods  -Version $Version -Detailed
    }
    else
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $NamespaceNativeMethods  -Version $Version
    }
}

function Remove-HnsNamespace
{
    param
    (
        [parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)]
        [Object[]] $InputObjects
    )
    begin {$objects = @()}
    process {$Objects += $InputObjects;}
    end {
        Remove-HnsGeneric -InputObjects $Objects -NativeMethods $NamespaceNativeMethods
    }
}

function Modify-HnsNamespace
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$true)] [ModifyRequestType] $RequestType,
        [parameter(Mandatory=$false)] [NamespaceResourceType] $ResourceType,
        [HashTable][parameter(Mandatory=$false)] $Settings
    )

    $msettings = @{
        RequestType = "$RequestType";
        ResourceType = "$ResourceType";
    }

    if ($Settings)
    {
        $msettings += @{
            Settings = $Settings;
        }
    }

    return Modify-HnsGeneric -Id $Id -NativeMethods $NamespaceNativeMethods -Settings $msettings
}

#########################################################################
# LoadBalancer
#########################################################################
Add-Type -TypeDefinition @"
    [System.Flags]
    public enum LoadBalancerFlags
    {
        None = 0,
        EnableDirectServerReturn = 1,
        EnableInternalLoadBalancer = 2,
    }
"@
function New-HnsLoadBalancer {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $true)] [int] $InternalPort,
        [parameter(Mandatory = $true)] [int] $ExternalPort,
        [parameter(Mandatory = $true)] [int] $Protocol,
        [parameter(Mandatory = $false)] [string] $Vip,
        [parameter(Mandatory = $false)] [string] $SourceVip,
        [parameter(Mandatory = $false)] [switch] $ILB,
        [parameter(Mandatory = $false)] [switch] $DSR
    )

    $portMapping = @{}
    $portMapping.InternalPort = $InternalPort
    $portMapping.ExternalPort = $ExternalPort
    $portMapping.Protocol = $Protocol
    $portmapping.Flags = [LoadBalancerFlags]0;
    if($ILB.IsPresent)
    {
        $portmapping.Flags = $portmapping.Flags -bor 1;
    }

   

    $LoadBalancers = @{
        HostComputeEndpoints = @(
            $Endpoints;
        );
        PortMappings = @(
            $portMapping
        );
        FrontendVIPs = @(
        );
        Flags = [LoadBalancerFlags]0;
        Policies = @();
        SchemaVersion = @{
                "Minor" = 2
                "Major" = 2
        }
	SourceVIP = $SourceVip
    }

   if($DSR.IsPresent)
    {
        $LoadBalancers.Flags = $LoadBalancers.Flags -bor 1;
    }

    if(-not [String]::IsNullOrEmpty($SourceVip))
    {
        $settings = @{
        }
        $LoadBalancers.Policies += @{
            Data = $settings;
        }
    }

    if(-not [String]::IsNullOrEmpty($vip))
    {
        $LoadBalancers.FrontendVIPs += $Vip
    }

    

    $id = [Guid]::Empty
    $settings = (ConvertTo-Json  $LoadBalancers -Depth 10) 
    $handle = 0
    $result = ""
    $hnsClientApi = Get-HnsClientNativeMethods
    $hr = $hnsClientApi::HcnCreateLoadBalancer($id, $settings, [ref] $handle, [ref] $result);
    ReportErrors -FunctionName HcnCreateLoadBalancer -Hr $hr -Result $result -ThrowOnFail

    $query = '{"SchemaVersion": { "Major": 1, "Minor": 0 }}'
    $properties = "";
    $result = ""
    $hr = $hnsClientApi::HcnQueryLoadBalancerProperties($handle, $query, [ref] $properties, [ref] $result);
    ReportErrors -FunctionName HcnQueryLoadBalancerProperties -Hr $hr -Result $result
    $hr = $hnsClientApi::HcnCloseLoadBalancer($handle);
    ReportErrors -FunctionName HcnCloseLoadBalancert -Hr $hr

    return ConvertResponseFromJson -JsonInput $properties
}

function Get-HnsPolioyList
{
    param
    (
        [parameter(Mandatory = $false)] [string] $Id = [Guid]::Empty,
        [parameter(Mandatory = $false)] [switch] $Detailed
    )
    if ($Detailed.IsPresent)
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $LoadBalancerNativeMethods -Detailed
    }
    else
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $LoadBalancerNativeMethods
    }
}

function Remove-HnsPolicyList
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [Object[]] $InputObjects
    )
    begin {$objects = @()}
    process {$Objects += $InputObjects;}
    end {
        Remove-HnsGeneric -InputObjects $Objects -NativeMethods $LoadBalancerNativeMethods
    }
}

function Get-HnsLoadBalancer
{
    param
    (
        [parameter(Mandatory = $false)] [Guid] $Id = [Guid]::Empty,
        [parameter(Mandatory=$false)] [int] $Version,
        [parameter(Mandatory=$false)] [switch] $Detailed
    )
    if ($Detailed.IsPresent)
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $LoadBalancerNativeMethods -Version $Version -Detailed
    }
    else
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $LoadBalancerNativeMethods -Version $Version
    }
}

function Remove-HnsLoadBalancer
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [Object[]] $InputObjects
    )
    begin {$objects = @()}
    process {$Objects += $InputObjects;}
    end {
        Remove-HnsGeneric -InputObjects $Objects -NativeMethods $LoadBalancerNativeMethods
    }
}

function Modify-HnsLoadBalancer
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$true)] [ModifyRequestType] $RequestType,
        [parameter(Mandatory=$false)] [LoadBalancerResourceType] $ResourceType,
        [HashTable][parameter(Mandatory=$false)] $Settings
    )

    $msettings = @{
        RequestType = "$RequestType";
        ResourceType = "$ResourceType";
    }

    if ($Settings)
    {
        $msettings += @{
            Settings = $Settings;
        }
    }

    return Modify-HnsGeneric -Id $Id -NativeMethods $LoadBalancerNativeMethods -Settings $msettings
}

#########################################################################
# Networks
#########################################################################
Add-Type -TypeDefinition @"
     [System.Flags]
    public enum NetworkFlags
    {
        None = 0,
        EnableDns = 1,
        EnableDhcp = 2,
        EnableMirroring = 4,
    }

    [System.Flags]
    public enum EndpointFlags
    {
        None = 0,
        RemoteEndpoint = 1,
        DisableICC = 2,
        EnableMirroring = 4,
    }
"@

function New-HnsIcsNetwork
{
    param
    (
        [parameter(Mandatory = $false)] [string] $Name,
        [parameter(Mandatory = $false)] [string] $AddressPrefix,
        [parameter(Mandatory = $false)] [string] $Gateway,
        [parameter(Mandatory= $false)] [NetworkFlags] $NetworkFlags = 0,
        [parameter(Mandatory= $false)] [int] $Vlan = 0,
        [parameter(Mandatory = $false)] [string] $DNSServer,
        [parameter(Mandatory = $false)] [int]    $ICSFlags = 0,
        [parameter(Mandatory = $false)] [string] $InterfaceConstraint = $null
    )
    $NetworkSpecificParams = @{
    }

    if ($InterfaceConstraint)
    {
        $NetworkSpecificParams += @{
            ExternalInterfaceConstraint = $InterfaceConstraint;
        }
    }

    $spolicy = @{}

    if ($Vlan -gt 0)
    {
        $spolicy += @{
            Type = "VLAN";
            VLAN = $Vlan;
        }
    }

    $NetworkSpecificParams += @{
        Flags = $NetworkFlags
    }

    return new-hnsnetwork -type ics `
        -Name $Name -AddressPrefix $AddressPrefix -Gateway $Gateway `
        -DNSServer $DNSServer `
        -AdditionalParams @{"ICSFlags" = $ICSFlags } `
        -NetworkSpecificParams $NetworkSpecificParams `
        -SubnetPolicies $spolicy
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
        [parameter(Mandatory = $false)] $AddressPrefix,
        [parameter(Mandatory = $false)] $Gateway,
        [HashTable[]][parameter(Mandatory=$false)] $SubnetPolicies, #  @(@{VSID = 4096; })

        [parameter(Mandatory = $false)] [switch] $IPv6,
        [parameter(Mandatory = $false)] [string] $DNSServer,
        [parameter(Mandatory = $false)] [string] $AdapterName,
        [HashTable][parameter(Mandatory=$false)] $AdditionalParams, #  @ {"ICSFlags" = 0; }
        [HashTable][parameter(Mandatory=$false)] $NetworkSpecificParams #  @ {"InterfaceConstraint" = ""; }
    )

    Begin {
        if (!$JsonString) {
            $netobj = @{
                Type = $Type;
            };

            if ($Name) {
                $netobj += @{
                    Name = $Name;
                }
            }

            # Coalesce prefix/gateway into subnet objects.
            if ($AddressPrefix) {
                $subnets += @()
                $prefixes = @($AddressPrefix)
                $gateways = @($Gateway)

                $len = $prefixes.length
                for ($i = 0; $i -lt $len; $i++) {
                    $subnet = @{ IpAddressPrefix = $prefixes[$i]; }
                    $routes = @()
                    if ($i -lt $gateways.length -and $gateways[$i]) {
                        $routes += @{ NextHop = $gateways[$i]; }         
                    }
                    $subnet +=  @{Routes = $routes} 
                    if ($SubnetPolicies) {
                            $subnet.Policies += $SubnetPolicies
                        }
                    $subnets += $subnet
                }

                $netobj += @{"Ipams" = @(@{Type= "Static";
                        "Subnets" = $subnets;
                             };)}        
            }
            if ($IPv6.IsPresent) {
                $netobj += @{ IPv6 = $true }
            }

            if ($AdapterName) {
                $netobj += @{ NetworkAdapterName = $AdapterName; }
            }

            if ($DNSServerList) {
                $list = $DNSServerList -Split ","
                $serverlist = @{
                    ServerList = $list;
                }
                $netobj += @{Dns = $serverlist}
            }

            if ($AdditionalParams) {
                $netobj += @{
                    AdditionalParams = @{}
                }

                foreach ($param in $AdditionalParams.Keys) {
                    $netobj.AdditionalParams += @{
                        $param = $AdditionalParams[$param];
                    }
                }
            }

            if ($NetworkSpecificParams) {
                $netobj += $NetworkSpecificParams
            }
            $netobj.SchemaVersion += @{
                "Minor" = 2
                "Major" = 2
        }
            $JsonString = ConvertTo-Json $netobj -Depth 10
        }

    }
    Process{
        $id = [Guid]::Empty
        $settings = $JsonString
        $handle = 0
        $result = ""
        $hnsClientApi = Get-HnsClientNativeMethods
        $hr = $hnsClientApi::HcnCreateNetwork($id, $settings, [ref] $handle, [ref] $result);
        ReportErrors -FunctionName HcnCreateNetwork -Hr $hr -Result $result -ThrowOnFail

        $query =  '{"SchemaVersion": { "Major": 1, "Minor": 0 }}'
        $properties = "";
        $result = ""
        $hr = $hnsClientApi::HcnQueryNetworkProperties($handle, $query, [ref] $properties, [ref] $result);
        ReportErrors -FunctionName HcnQueryNetworkProperties -Hr $hr -Result $result
        $hr = $hnsClientApi::HcnCloseNetwork($handle);
        ReportErrors -FunctionName HcnCloseNetwork -Hr $hr

        return ConvertResponseFromJson -JsonInput $properties
    }
}

function Get-HnsNetwork
{
    param
    (
        [parameter(Mandatory=$false)] [Guid] $Id = [Guid]::Empty,
        [parameter(Mandatory=$false)] [switch] $Detailed,
        [parameter(Mandatory=$false)] [int] $Version
    )
    if($Detailed.IsPresent)
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $NetworkNativeMethods -Version $Version -Detailed
    }
    else
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $NetworkNativeMethods -Version $Version
    }
}

function Modify-HnsNetworkDNS
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$false)] [String] $Suffix = "",
        [parameter(Mandatory=$false)] [String[]] $Search = "",
        [parameter(Mandatory=$false)] [String[]] $ServerList = "",
        [parameter(Mandatory=$false)] [String[]] $Options = "",
        [parameter(Mandatory=$true)] [ModifyRequestType] $RequestType,
        [parameter(Mandatory=$false)] [NetworkResourceType] $ResourceType
    )
    $settings = @{
        Suffix = $Suffix;
        Search = $Search;
        ServerList = $ServerList;
        Options = $Options;
    }
    Modify-HnsNetwork -Id $Id -RequestType $RequestType -ResourceType $ResourceType -Settings $Settings
}

function Update-HnsNetworkDNS
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$false)] [String] $Suffix = "",
        [parameter(Mandatory=$false)] [String[]] $Search = @(),
        [parameter(Mandatory=$false)] [String[]] $ServerList = @(),
        [parameter(Mandatory=$false)] [String[]] $Options = @()
    )
    $RequestType = [ModifyRequestType]::Update
    $ResourceType = [NetworkResourceType]::DNS
    Modify-HnsNetworkDNS -Id $Id -RequestType $RequestType -ResourceType $ResourceType -Suffix `
      $Suffix -Search $Search -ServerList $ServerList -Options $Options
}

function Update-HnsNetworkExtension
{
    param
    (
        [parameter (Mandatory=$true)] [Guid] $Id,
        [parameter (Mandatory=$false)] [Guid] $ExtensionId,
        [parameter (Mandatory=$false)] [bool] $IsEnabled
    )
    $RequestType = [ModifyRequestType]::Update
    $ResourceType = [NetworkResourceType]::Extension
    $settings = @{
               Id = $ExtensionId;
               IsEnabled = $IsEnabled;
    }
    Modify-HnsNetwork -Id $Id -RequestType $RequestType -ResourceType $ResourceType -Settings $Settings
}

function Remove-HnsNetwork
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [Object[]] $InputObjects
    )
    begin {$objects = @()}
    process {$Objects += $InputObjects;}
    end {
        Remove-HnsGeneric -InputObjects $Objects -NativeMethods $NetworkNativeMethods
    }
}

function Modify-HnsNetwork
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$true)] [ModifyRequestType] $RequestType,
        [parameter(Mandatory=$false)] [NetworkResourceType] $ResourceType,
        [HashTable][parameter(Mandatory=$false)] $Settings
    )

    $msettings = @{
        RequestType = "$RequestType";
        ResourceType = "$ResourceType";
    }

    if ($Settings)
    {
        $msettings += @{
            Settings = $Settings;
        }
    }

    return Modify-HnsGeneric -Id $Id -NativeMethods $NetworkNativeMethods -Settings $msettings
}
#########################################################################
# Endpoints
#########################################################################

function New-HnsEndpoint
{
    param
    (
        [parameter(Mandatory=$false, Position = 0)] [string] $JsonString = $null,
        [parameter(Mandatory = $true, Position = 0)] [Guid] $NetworkId,
        [parameter(Mandatory = $false)] [string] $Name,
        [parameter(Mandatory = $false)] [string] $IPAddress,
        [parameter(Mandatory = $false)] [string] $IPv6Address,
        [parameter(Mandatory = $false)] [string] $GatewayAddress,
        [parameter(Mandatory = $false)] [string] $GatewayAddressV6,
        [parameter(Mandatory = $false)] [string] $DNSServerList,
        [parameter(Mandatory = $false)] [string] $MacAddress,
        [parameter(Mandatory = $false)] [switch] $RemoteEndpoint,
        [parameter(Mandatory = $false)] [switch] $EnableOutboundNat,
        [parameter(Mandatory = $false)] [string[]] $OutboundNatExceptions,
        [parameter(Mandatory = $false)] [string[]] $RoutePrefixes, # Deprecate this. use RoutePolicies
        [HashTable[]][parameter(Mandatory=$false)] $RoutePolicies, #  @( @ {"DestinationPrefix" = ""; "NeedEncap" = true; "NextHop" = ""} )
        [HashTable][parameter(Mandatory=$false)] $InboundNatPolicy, #  @ {"InternalPort" = "80"; "ExternalPort" = "8080"}
        [HashTable][parameter(Mandatory=$false)] $PAPolicy #  @ {"PA" = "1.2.3.4"; }
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
                HostComputeNetwork = $NetworkId;
                Policies       = @();
                SchemaVersion = @{
                    "Minor" = 2;
                    "Major" = 2;
                };
            }

            if ($Name) {
                $endpoint += @{
                    Name = $Name;
                }
            }

            if ($MacAddress) {
                $endpoint += @{
                    MacAddress = $MacAddress;
                }
            }
            $IpConfigurations = @();
            $Routes = @()         
            
            if ($IPAddress) {
                $IpConfigurations += @{
                    IpAddress      = $IPAddress;
                }
            }
            if ($GatewayAddress) {
                $routes += @{ NextHop = $GatewayAddress; DestinationPrefix = "0.0.0.0/0"}
            }
           
            if ($IPv6Address) {
                $IpConfigurations += @{
                    IpAddress = $IPv6Address;
                }
            }
            
            if ($GatewayAddressV6) {
                $routes += @{ NextHop = $GatewayAddressV6; DestinationPrefix = "::/0"}
            }

            $endpoint += @{IpConfigurations = $IpConfigurations}
            $endpoint += @{Routes = $Routes}
            
            if ($DNSServerList) {
                $list = $DNSServerList -Split ","
                $serverlist = @{
                    ServerList = $list;
                }
                $endpoint += @{Dns = $serverlist}
            }
            if ($RemoteEndpoint.IsPresent) {
                $endpoint += @{Flags= 1;}
            }

            if ($EnableOutboundNat.IsPresent) {

                $outboundPolicy = @{}
                $outboundPolicy.Type = "OutBoundNAT"
                $outboundPolicy.Settings = @{}
                if ($OutboundNatExceptions) {
                    $ExceptionList = @()
                    foreach ($exp in $OutboundNatExceptions)
                    {
                        $ExceptionList += $exp
                    }
                    $Settings += @{Exceptions = $ExceptionList}
                }

                $endpoint.Policies +=  $outboundPolicy;
            }

            if ($RoutePolicies)
            {
                foreach ($routepolicy in $RoutePolicies)
                {
                    $rPolicy = @{
                        DestinationPrefix = $routepolicy["DestinationPrefix"];
                        NeedEncap = $true;
                    }
                    if ($routepolicy.ContainsKey("NextHop"))
                    {
                        $rPolicy.NextHop = $routepolicy["NextHop"]
                    }
                    $Settings = @{
                        Type = "SDNRoute";
                        Settings = $rPolicy;
                    }
                    $endpoint.Policies += $Settings;
                    }
                }
            }

            # Deprecate this
            if ($RoutePrefixes)
            {
                foreach ($routeprefix in $RoutePrefixes) {
                    $endpoint.Routes += @{
                            DestinationPrefix = $routeprefix;
                            NeedEncap = $true;
                    }
                }
            }

            if ($InboundNatPolicy) {
                $endpoint.Policies += @{
                    Type = "PortMapping";
                    Settings = @{
                        InternalPort = $InboundNatPolicy["InternalPort"];
                        ExternalPort = $InboundNatPolicy["ExternalPort"];
                    };
                }
            }

            if ($PAPolicy) {
                $endpoint.Policies += @{
                    Type = "ProviderAddress";
                    Settings = @{
                        ProviderAddress = $PAPolicy["PA"];
                    }
                }
            }

            # Try to Generate the data
            $EndpointData = convertto-json $endpoint -Depth 10
        }


    Process
    {
        $id = [Guid]::Empty
        $settings = $EndpointData
        $handle = 0
        $result = ""
        $networkHandle = 0
        $hnsClientApi = Get-HnsClientNativeMethods
        $hr = $hnsClientApi::HcnOpenNetwork($NetworkId, [ref] $networkHandle, [ref] $result);
        ReportErrors -FunctionName HcnOpenNetwork -Hr $hr -Result $result -ThrowOnFail
        $result = ""
        $hr = $hnsClientApi::HcnCreateEndpoint($networkHandle, $id, $settings, [ref] $handle, [ref] $result);
        ReportErrors -FunctionName HcnCreateEndpoint -Hr $hr -Result $result -ThrowOnFail

        $query =  '{"SchemaVersion": { "Major": 1, "Minor": 0 }}'
        $properties = "";
        $result = ""
        $hr = $hnsClientApi::HcnQueryEndpointProperties($handle, $query, [ref] $properties, [ref] $result);
        ReportErrors -FunctionName HcnQueryEndpointProperties -Hr $hr -Result $result
        $hr = $hnsClientApi::HcnCloseEndpoint($handle);
        ReportErrors -FunctionName HcnCloseEndpoint -Hr $hr
        $hr = $hnsClientApi::HcnCloseNetwork($networkHandle);
        ReportErrors -FunctionName HcnCloseNetwork -Hr $hr

        return ConvertResponseFromJson -JsonInput $properties
    }
}

function New-HnsRemoteEndpoint
{
    param
    (
        [parameter(Mandatory = $true)] [Guid] $NetworkId,
        [parameter(Mandatory = $false)] [string] $IPAddress,
        [parameter(Mandatory = $false)] [string] $MacAddress,
        [parameter(Mandatory = $false)] [string] $DNSServerList
    )

    return New-HnsEndpoint -NetworkId $NetworkId -IPAddress $IPAddress -MacAddress $MacAddress -DNSServerList $DNSServerList -RemoteEndpoint
}
function Get-HnsEndpoint
{
    param
    (
        [parameter(Mandatory=$false)] [Guid] $Id = [Guid]::Empty,
        [parameter(Mandatory=$false)] [Guid] $NetworkId = [Guid]::Empty,
        [parameter(Mandatory=$false)] [string] $NetworkName = "",
        [parameter(Mandatory=$false)] [int] $Version,
        [parameter(Mandatory=$false)] [switch] $Detailed

    )

    $Filter = @{}
    if(-NOT [String]::IsNullOrEmpty($NetworkName))
    {
        $Filter += @{
            VirtualNetworkName = $NetworkName;
        }
    }
    if($NetworkId -NE [Guid]::Empty)
    {
        $Filter += @{
            VirtualNetwork = $NetworkId;
        }
    }
    if($Detailed.IsPresent)
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $EndpointNativeMethods -Filter $Filter -Version $Version -Detailed
    }
    else
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $EndpointNativeMethods -Filter $Filter -Version $Version
    }   
}

function Modify-HnsEndpoint
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$true)] [ModifyRequestType] $RequestType,
        [parameter(Mandatory=$false)] [EndpointResourceType] $ResourceType,
        [HashTable][parameter(Mandatory=$false)] $Settings,
        [HashTable[]][parameter(Mandatory=$false)] $PolicyArray
    )

    $msettings = @{
        RequestType = "$RequestType";
        ResourceType = "$ResourceType";
    }

    if ($Settings)
    {
        $msettings += @{
            Settings = $Settings;
        }
    }
    elseif($PolicyArray)
    {
        $policies = @{
            Policies = $PolicyArray;
        }
        $msettings += @{
            Settings = $policies;
        }
    }

    return Modify-HnsGeneric -Id $Id -NativeMethods $EndpointNativeMethods -Settings $msettings
}



function Add-HnsEndpointVmPort
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$false)] [Guid]$PortId,
        [parameter(Mandatory=$false)] [Guid]$VirtualMachineId
    )

    $settings = @{
        PortId = $PortId;
        VirtualMachineId = $VirtualMachineId;
        VirtualNicName = "$VirtualMachineId--$Id"
    }
    $requestType = [ModifyRequestType]::Add
    $resourceType = [EndpointResourceType]::Port
    Modify-HnsEndpoint -Id $Id -RequestType $requestType -ResourceType $resourceType -Settings $settings
}

function Remove-HnsEndpointVmPort
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id
    )

    $settings = @{}
    $requestType = [ModifyRequestType]::Remove
    $resourceType = [EndpointResourceType]::Port
    Modify-HnsEndpoint -Id $Id -RequestType $requestType -ResourceType $resourceType -Settings $settings
}

function Remove-HnsEndpoint
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)]
        [Object[]] $InputObjects
    )
    begin {$objects = @()}
    process {$Objects += $InputObjects;}
    end {
        Remove-HnsGeneric -InputObjects $Objects -NativeMethods $EndpointNativeMethods
    }
}

function Update-HnsEndpointPolicy {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $Policies 
    )
    $requestType = [ModifyRequestType]::Update
    $resourceType = [EndpointResourceType]::Policy
    foreach ($id in $Endpoints) {
        $ep = Get-HnsEndpoint -Id $id -Version 2
        Modify-HnsEndpoint -Id $Id -RequestType $requestType -ResourceType $resourceType -PolicyArray $Policies
    }
}

function New-HnsProxyPolicy {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $false)] [string] $DestinationPrefix,
        [parameter(Mandatory = $false)] [string] $DestinationPort,
        [parameter(Mandatory = $false)] [string] $Destination,
        [parameter(Mandatory = $false)] [string[]] $ExceptionList,
        [parameter(Mandatory = $false)] [bool] $OutboundNat
    )
    $ProxyPolicy = @{}
    $Type = "L4Proxy";
		
    if ($DestinationPrefix) {
        $ProxyPolicy['IP'] = $DestinationPrefix
    }
    if ($DestinationPort) {
        $ProxyPolicy['Port'] = $DestinationPort
    }
    if ($ExceptionList) {
        $ProxyPolicy['ExceptionList'] = $ExceptionList
    }
    if ($Destination) {
        $ProxyPolicy['Destination'] = $Destination
    }
    if ($OutboundNat) {
        $ProxyPolicy['OutboundNat'] = $OutboundNat
    }
    
    $Settings   = @{
            Type = $type;
            Settings = $ProxyPolicy;
    };
    Update-HnsEndpointPolicy -Endpoints $Endpoints -Settings @($Settings)
    
}

function Remove-HnsProxyPolicy {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null
    )
    
    Update-HnsEndpointPolicy -Endpoints $Endpoints -Settings @(@{})
}




################################
# GuestNetworkService
################################
Add-Type -TypeDefinition @"
    public enum GuestNetworkServiceResourceType
    {
        State,
    };

    public enum GuestNetworkServiceState
    {
        None,
        Paused,
        Ready, 
    };
"@

function Get-HnsGuestNetworkService
{
    param
    (
        [parameter(Mandatory=$false)] [Guid] $Id = [Guid]::Empty,
        [parameter(Mandatory=$false)] [switch] $Detailed,
        [parameter(Mandatory=$false)] [int] $Version
    )
    if ($Detailed.IsPresent)
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $GuestNetworkServiceNativeMethods -Version $Version -Detailed
    }
    else
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $GuestNetworkServiceNativeMethods -Version $Version
    }
}

function Modify-HnsGuestNetworkService
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$true)] [ModifyRequestType] $RequestType,
        [parameter(Mandatory=$false)] [GuestNetworkServiceResourceType] $ResourceType,
        [HashTable][parameter(Mandatory=$false)] $Settings
    )
    $msettings = @{
        RequestType = "$RequestType";
        ResourceType = "$ResourceType";
    }

    if ($Settings)
    {
        $msettings += @{
            Settings = $Settings;
        }
    }

    return Modify-HnsGeneric -Id $Id -NativeMethods $GuestNetworkServiceNativeMethods -Settings $msettings
}

function Modify-HnsGuestNetworkServiceState
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $Id,
        [parameter(Mandatory=$true)] [GuestNetworkServiceState] $State
    )
    $requestType = [ModifyRequestType]::Update
    $resourceType = [GuestNetworkServiceResourceType]::State
    Modify-HnsGuestNetworkService -Id $Id -RequestType $requestType -ResourceType $resourceType -Settings @{ State = "$State"}
}

function ReportErrors
{
    param
    (
        [parameter(Mandatory=$false)]
        [string] $FunctionName,
        [parameter(Mandatory=$true)]
        [Int64] $Hr,
        [parameter(Mandatory=$false)]
        [string] $Result,
        [switch] $ThrowOnFail
    )

    $errorOutput = ""

    if($Hr -ne 0)
    {
        $errorOutput += "HRESULT: $($Hr). "
    }

    if(-NOT [string]::IsNullOrWhiteSpace($Result))
    {
        $errorOutput += "Result: $($Result)"
    }

    if(-NOT [string]::IsNullOrWhiteSpace($errorOutput))
    {
        $errString = "$($FunctionName) -- $($errorOutput)"
        if($ThrowOnFail.IsPresent)
        {
            throw $errString
        }
        else {
            Write-Error $errString
        }
    }
}

function ConvertResponseFromJson
{
    param
    (
        [parameter(Mandatory=$false)]
        [string] $JsonInput
    )

    $output = "";
    if ($JsonInput)
    {
        try {
            $output = ($JsonInput | ConvertFrom-Json);
        } catch {
            Write-Error $_.Exception.Message
            return ""
        }
        if ($output.Error)
        {
             Write-Error $output;
        }
    }

    return $output;
}

#########################################################################

Export-ModuleMember -Function New-HnsNetwork
Export-ModuleMember -Function New-HnsIcsNetwork
Export-ModuleMember -Function Get-HnsNetwork
Export-ModuleMember -Function Remove-HnsNetwork
Export-ModuleMember -Function Modify-HnsNetwork
Export-ModuleMember -Function Update-HnsNetworkDNS
Export-ModuleMember -Function Update-HnsNetworkExtension


Export-ModuleMember -Function New-HnsEndpoint
Export-ModuleMember -Function New-HnsRemoteEndpoint
Export-ModuleMember -Function Get-HnsEndpoint
Export-ModuleMember -Function Modify-HnsEndpoint
Export-ModuleMember -Function Update-HnsEndpointPolicy
Export-ModuleMember -Function Add-HnsEndpointVmPort
Export-ModuleMember -Function Remove-HnsEndpointVmPort
Export-ModuleMember -Function Remove-HnsEndpoint


Export-ModuleMember -Function New-HnsNamespace
Export-ModuleMember -Function Get-HnsNamespace
Export-ModuleMember -Function Remove-HnsNamespace
Export-ModuleMember -Function Modify-HnsNamespace

Export-ModuleMember -Function New-HnsLoadBalancer
Export-ModuleMember -Function Get-HnsLoadBalancer
Export-ModuleMember -Function Remove-HnsLoadBalancer
Export-ModuleMember -Function Modify-HnsLoadBalancer

Export-ModuleMember -Function New-HnsProxyPolicy
Export-ModuleMember -Function Remove-HnsProxyPolicy

Export-ModuleMember -Function Get-HnsGuestNetworkService
Export-ModuleMember -Function Modify-HnsGuestNetworkService
Export-ModuleMember -Function Modify-HnsGuestNetworkServiceState
