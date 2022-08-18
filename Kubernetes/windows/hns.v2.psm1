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
        public static extern System.Int64 HcnQueryEndpointStats(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Endpoint,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Stats,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);
        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnQueryEndpointAddresses(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr Endpoint,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Addresses,
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
        // SdnRoute
        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnEnumerateSdnRoutes(
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Routes,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);
        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCreateSdnRoute(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr SdnRoute,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);
        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnOpenSdnRoute(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.SysUInt)]
            out IntPtr SdnRoute,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);
        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnModifySdnRoute(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr SdnRoute,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Settings,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);
        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnQuerySdnRouteProperties(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr SdnRoute,
            [MarshalAs(UnmanagedType.LPWStr)]
            string Query,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Properties,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);
        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnDeleteSdnRoute(
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid Id,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string Result);
        [DllImport("computenetwork.dll")]
        public static extern System.Int64 HcnCloseSdnRoute(
            [MarshalAs(UnmanagedType.SysUInt)]
            IntPtr SdnRoute);
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
        Policy,
        Subnet,
        IPSubnet
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

$SdnRouteNativeMethods = @{
    Open = $ClientNativeMethods::HcnOpenSdnRoute;
    Close = $ClientNativeMethods::HcnCloseSdnRoute;
    Enumerate = $ClientNativeMethods::HcnEnumerateSdnRoutes;
    Delete = $ClientNativeMethods::HcnDeleteSdnRoute;
    Query = $ClientNativeMethods::HcnQuerySdnRouteProperties;
    Modify = $ClientNativeMethods::HcnModifySdnRoute;
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
    if($Version -eq 1)
    {
        $query += @{SchemaVersion = @{ Major = 1; Minor = 0 }}
    }
    else
    {
        $query += @{SchemaVersion = @{ Major = 2; Minor = 0 }}
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
        [parameter(Mandatory = $false)] [switch] $Default,
        [parameter(Mandatory = $false)] [bool] $createWithCompartment = $false
    )

   if([bool]$Default) {
        $namespace=@{Type= "HostDefault"; 
	    CreateWithCompartment = $createWithCompartment;
            SchemaVersion = @{
                "Minor" = 2
                "Major" = 2
        }}
    }
    else
    {
        $namespace=@{CreateWithCompartment = $createWithCompartment;
		SchemaVersion = @{
                "Minor" = 2
                "Major" = 2
        }}
    }

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

    if($null -ne $Endpoints)
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
    public enum LoadBalancerDistribution
    {
        None = 0,
        SourceIPProtocol = 1,
        SourceIP = 2,
    };
    [System.Flags]
    public enum LoadBalancerFlags
    {
        None = 0,
        EnableDirectServerReturn = 1,
        IPv6 = 2,
    }
    [System.Flags]
    public enum LoadBalancerPortMappingFlags
    {
        None = 0,
        EnableInternalLoadBalancer = 1,
        LocalRoutedVip = 2,
        EnablePreserveDip = 8,
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
        [parameter(Mandatory = $false)] [switch] $LocalRoutedVip,
        [parameter(Mandatory = $false)] [switch] $ILB,
        [parameter(Mandatory = $false)] [switch] $DSR,
        [parameter(Mandatory = $false)] [switch] $PreserveDip,
        [parameter(Mandatory = $false)] [string] $LoadBalancerDistribution,
        [parameter(Mandatory = $false)] [switch] $IPv6
    )

    $portMapping = @{}
    $portMapping.InternalPort = $InternalPort
    $portMapping.ExternalPort = $ExternalPort
    $portMapping.Protocol = $Protocol
    $portMapping.DistributionType = [LoadBalancerDistribution]::None;
    if ($LoadBalancerDistribution -eq "SourceIPProtocol")
    {
        $portMapping.DistributionType = [LoadBalancerDistribution]::SourceIPProtocol
    }
    elseif ($LoadBalancerDistribution -eq "SourceIP")
    {
        $portMapping.DistributionType = [LoadBalancerDistribution]::SourceIP
    }
    $portmapping.Flags = [LoadBalancerPortMappingFlags]::None;
    if($ILB.IsPresent)
    {
        $portmapping.Flags = $portmapping.Flags -bor [LoadBalancerPortMappingFlags]::EnableInternalLoadBalancer;
    }
    if($LocalRoutedVip.IsPresent)
    {
        $portmapping.Flags = $portmapping.Flags -bor [LoadBalancerPortMappingFlags]::LocalRoutedVip;
    }
    if($DSR.IsPresent)
    {
        if($PreserveDip.IsPresent)
        {
            $portmapping.Flags = $portmapping.Flags -bor [LoadBalancerPortMappingFlags]::EnablePreserveDip;
        }
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
        Flags = [LoadBalancerFlags]::None;
        SchemaVersion = @{
                "Minor" = 2
                "Major" = 2
        }
    SourceVIP = $SourceVip
    }

    if($DSR.IsPresent)
    {
        $LoadBalancers.Flags = $LoadBalancers.Flags -bor [LoadBalancerFlags]::EnableDirectServerReturn;
    }

    if($IPv6.IsPresent)
    {
        $LoadBalancers.Flags = $LoadBalancers.Flags -bor [LoadBalancerFlags]::IPv6;
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
    ReportErrors -FunctionName HcnCloseLoadBalancer -Hr $hr

    return ConvertResponseFromJson -JsonInput $properties
}

function Get-HnsPolicyList
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
# SdnRoute
#########################################################################
function New-HnsRoute {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $true)] [string] $DestinationPrefix,
        [parameter(Mandatory = $false)] [switch] $EncapEnabled,
        [parameter(Mandatory = $false)] [string] $NextHop,
        [parameter(Mandatory = $false)] [switch] $MonitorDynamicEndpoints
    )

    $SDNRoutePolicySetting = @{
        DestinationPrefix = $DestinationPrefix;
        NextHop = $NextHop;
        NeedEncap = $EncapEnabled.IsPresent;
        AutomaticEndpointMonitor = $MonitorDynamicEndpoints.IsPresent;
    }

    $HostComputeRoute = @{
        HostComputeEndpoints = @(
            $Endpoints;
        );
        Routes = @(
            $SDNRoutePolicySetting
        );
        SchemaVersion = @{
                "Minor" = 2
                "Major" = 2
        }
    }

    $id = [Guid]::Empty
    $settings = (ConvertTo-Json  $HostComputeRoute -Depth 10)
    $handle = 0
    $result = ""
    $hnsClientApi = Get-HnsClientNativeMethods
    $hr = $hnsClientApi::HcnCreateSdnRoute($id, $settings, [ref] $handle, [ref] $result);
    ReportErrors -FunctionName HcnCreateSdnRoute -Hr $hr -Result $result -ThrowOnFail

    $query = '{"SchemaVersion": { "Major": 1, "Minor": 0 }}'
    $properties = "";
    $result = ""
    $hr = $hnsClientApi::HcnQuerySdnRouteProperties($handle, $query, [ref] $properties, [ref] $result);
    ReportErrors -FunctionName HcnQuerySdnRouteProperties -Hr $hr -Result $result
    $hr = $hnsClientApi::HcnCloseSdnRoute($handle);
    ReportErrors -FunctionName HcnCloseSdnRoute -Hr $hr

    return ConvertResponseFromJson -JsonInput $properties
}

function Get-HnsRoute
{
    param
    (
        [parameter(Mandatory = $false)] [Guid] $Id = [Guid]::Empty,
        [parameter(Mandatory=$false)] [int] $Version,
        [parameter(Mandatory=$false)] [switch] $Detailed
    )
    if ($Detailed.IsPresent)
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $SdnRouteNativeMethods -Version $Version -Detailed
    }
    else
    {
        return Get-HnsGeneric -Id $Id -NativeMethods $SdnRouteNativeMethods -Version $Version
    }
}

function Remove-HnsRoute
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
        Remove-HnsGeneric -InputObjects $Objects -NativeMethods $SdnRouteNativeMethods
    }
}

#########################################################################
# Networks
#########################################################################
# Add missing Network types if necessary
if (-Not ("NetworkFlags" -as [type]))
{
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
            EnableLowInterfaceMetric = 8,
            OverrideDNSServerOrder = 16,
            EnableDhcp = 32
        }
        [System.Flags]
        public enum IPSubnetFlags
        {
            None = 0,
            EnableBroadcast = 1,
            ReserveNetworkAddress = 2,
        }
"@
}

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
        $NetworkSpecificParams.Policies += @{
            "Type" = "INTERFACECONSTRAINT";
            "Settings" = $InterfaceConstraint;
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
        -vlan $vlan
}
function New-HnsNetwork
{
    param
    (
        [parameter(Mandatory=$false, Position=0)]
        [string] $JsonString,
        [ValidateSet('ICS', 'Internal', 'Transparent', 'NAT', 'Overlay', 'L2Bridge', 'L2Tunnel', 'Layered', 'Private', 'Infiniband')]
        [parameter(Mandatory = $false, Position = 0)]
        [string] $Type,
        [parameter(Mandatory = $false)] [string] $Name,
        [parameter(Mandatory = $false)] $AddressPrefix,
        [parameter(Mandatory = $false)] $IPSubnets, # @(@{"IpAddressPrefix"="192.168.1.0/24";"Flags"=0},@{"IpAddressPrefix"="192.168.2.0/24";"Flags"=0})
        [parameter(Mandatory = $false)] $Gateway,
        [parameter(Mandatory= $false)] [int] $Vlan = 0,
        [parameter(Mandatory= $false)] [int] $Vsid = 0,
        [parameter(Mandatory = $false)] [switch] $IPv6,
        [parameter(Mandatory = $false)] [string] $DNSServer,
        [parameter(Mandatory = $false)] [string] $AdapterName,
        [HashTable][parameter(Mandatory=$false)] $AdditionalParams, #  @ {"ICSFlags" = 0; }
        [HashTable][parameter(Mandatory=$false)] $NetworkSpecificParams, #  @ {"InterfaceConstraint" = ""; }
        [parameter(Mandatory = $false)] [int] $VxlanPort = 0,
        [parameter(Mandatory = $false)] [bool] $AutomaticDnsEnabled = $false,
        [parameter(Mandatory = $false)] [Guid] $LayerId
    )

    Begin {
        if (!$JsonString) {
            $netobj = @{
                Type = $Type;
                Policies = @();
            };

            if ($Name) {
                $netobj += @{
                    Name = $Name;
                }
            }

            if ($NetworkSpecificParams) {
                $netobj += $NetworkSpecificParams
            }
            # Coalesce prefix/gateway into subnet objects.
            if ($AddressPrefix) {
                $ipams = @()
                $ipam = @{
                    Type = "Static";
                }

                $subnets += @()
                $prefixes = @($AddressPrefix)
                $gateways = @($Gateway)

                $len = $prefixes.length
                for ($i = 0; $i -lt $len; $i++) {
                    $subnet = @{ IpAddressPrefix = $prefixes[$i]; }
                    $routes = @()
                    if ($i -lt $gateways.length -and $gateways[$i]) {
                        $routes += @{
                            NextHop = $gateways[$i];
                            DestinationPrefix = "0.0.0.0/0";
                        }
                    }
                    $subnet +=  @{
                        Routes = $routes
                    }
                    $Subnet.Policies = @()
                    if ($vlan -gt 0) {
                        $subnet.Policies += @{"Type"= "VLAN"; "Settings" = @{"IsolationId" = $VLAN}}
                    }
                    if ($Vsid -gt 0) {
                        $subnet.Policies += @{"Type"= "VSID"; "Settings" = @{"IsolationId" = $VSID}}
                    }

                    $Subnet.IpSubnets = $IPSubnets

                    $subnets += $subnet
                }

                $ipam += @{
                    Subnets = $subnets;
                }
                $ipams += $ipam;
                $netobj += @{
                    Ipams = $ipams;
                }
            }
            if ($IPv6.IsPresent) {
                $netobj += @{ IPv6 = $true }
            }

            if ($AdapterName) {
                $netobj.Policies += @{"Type"= "NetAdapterName"; "Settings" = @{"NetworkAdapterName" = $AdapterName}}
            }

            if ($LayerId) {
                $netobj.Policies += @{"Type"= "LayerConstraint"; "Settings" = @{"LayerId" = $LayerId}}
            }

            if ($DNSServer) {
                $list = $DNSServer -split ","
                $netobj += @{Dns = @{ ServerList = $list}}
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

            if ($VxlanPort -gt 0) {
                $netobj.Policies += @{ "Type" = "VxlanPort"; "Settings" = @{ "Port" = $VxlanPort }}
            }

            if ($AutomaticDnsEnabled)
            {
                $netobj.Policies += @{ "Type" = "AutomaticDNS"; "Settings" = @{ "Enable" = $true }}
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
        [parameter(Mandatory=$false)] [String] $Domain = "",
        [parameter(Mandatory=$false)] [String[]] $Search = "",
        [parameter(Mandatory=$false)] [String[]] $ServerList = "",
        [parameter(Mandatory=$false)] [String[]] $Options = "",
        [parameter(Mandatory=$true)] [ModifyRequestType] $RequestType,
        [parameter(Mandatory=$false)] [NetworkResourceType] $ResourceType
    )
    $settings = @{
        Domain = $Domain;
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
        [parameter(Mandatory=$false)] [String] $Domain = "",
        [parameter(Mandatory=$false)] [String[]] $Search = @(),
        [parameter(Mandatory=$false)] [String[]] $ServerList = @(),
        [parameter(Mandatory=$false)] [String[]] $Options = @()
    )
    $RequestType = [ModifyRequestType]::Update
    $ResourceType = [NetworkResourceType]::DNS
    Modify-HnsNetworkDNS -Id $Id -RequestType $RequestType -ResourceType $ResourceType -Domain `
      $Domain -Search $Search -ServerList $ServerList -Options $Options
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

function New-HnsNetworkPolicy
{
    param
    (
        [parameter(Mandatory = $false)] [Guid] $NetworkId = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $Policies
    )
    $requestType = [ModifyRequestType]::Add
    $resourceType = [NetworkResourceType]::Policy
    Modify-HnsNetwork -Id $NetworkId -RequestType $requestType -ResourceType $resourceType -PolicyArray $Policies
}

function Update-HnsNetworkPolicy
{
    param
    (
        [parameter(Mandatory = $false)] [Guid] $NetworkId = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $Policies
    )
    $requestType = [ModifyRequestType]::Update
    $resourceType = [NetworkResourceType]::Policy  
    Modify-HnsNetwork -Id $NetworkId -RequestType $requestType -ResourceType $resourceType -PolicyArray $Policies 
}

function Remove-HnsNetworkPolicy
{
    param
    (
        [parameter(Mandatory = $false)] [Guid] $NetworkId = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $Policies
    )
    $requestType = [ModifyRequestType]::Remove
    $resourceType = [NetworkResourceType]::Policy
    Modify-HnsNetwork -Id $NetworkId -RequestType $requestType -ResourceType $resourceType -PolicyArray $Policies
}

function New-HnsRemoteSubnetRoutePolicy
{
    param
    (
        [parameter (Mandatory = $true)] [Guid] $NetworkId,
        [parameter (Mandatory = $true)] [string] $DestinationPrefix,
        [parameter (Mandatory = $true)] [int] $IsolationId,
        [parameter (Mandatory = $true)] [string] $ProviderAddress,
        [parameter (Mandatory = $true)] [string] $DistributedRouterMacAddress
    )
    $Type = "RemoteSubnetRoute";
    $rsPolicy = @{
                DestinationPrefix = $DestinationPrefix;
                IsolationId = $IsolationId;
                ProviderAddress = $ProviderAddress;
                DistributedRouterMacAddress = $DistributedRouterMacAddress;
    }
    $settings = @{
        Type = $Type;
        Settings = $rsPolicy;
    }
    New-HnsNetworkPolicy -NetworkId $NetworkId -Policies @($Settings)
}

function Remove-HnsRemoteSubnetRoutePolicy
{
    param
    (
        [parameter (Mandatory = $true)] [Guid] $NetworkId,
        [parameter (Mandatory = $true)] [string] $DestinationPrefix,
        [parameter (Mandatory = $true)] [int] $IsolationId,
        [parameter (Mandatory = $true)] [string] $ProviderAddress,
        [parameter (Mandatory = $true)] [string] $DistributedRouterMacAddress
    )
    $Type = "RemoteSubnetRoute";
    $rsPolicy = @{
        DestinationPrefix = $DestinationPrefix;
        IsolationId = $IsolationId;
        ProviderAddress = $ProviderAddress;
        DistributedRouterMacAddress = $DistributedRouterMacAddress;
}
    $settings = @{
        Type = $Type;
        Settings = $rsPolicy;
    }
    Remove-HnsNetworkPolicy -NetworkId $NetworkId -Policies @($Settings)
}

function New-HnsHostRoutePolicy
{
    param
    (
        [parameter (Mandatory = $true)] [Guid] $NetworkId
    )

    $Type = "HostRoute";
    $rsPolicy = @{
    }
    $settings = @{
        Type = $Type;
        Settings = $rsPolicy;
    }
    New-HnsNetworkPolicy -NetworkId $NetworkId -Policies @($Settings)
}

function Remove-HnsHostRoutePolicy
{
    param
    (
        [parameter (Mandatory = $true)] [Guid] $NetworkId
    )

    $Type = "HostRoute";
    $rsPolicy = @{
    }
    $settings = @{
        Type = $Type;
        Settings = $rsPolicy;
    }
    Remove-HnsNetworkPolicy -NetworkId $NetworkId -Policies @($Settings)
}

function New-HnsNeighborDiscoveryPolicy
{
    param
    (
        [parameter (Mandatory = $true)] [Guid] $NetworkId,
        [parameter (Mandatory = $true)] [string] $TargetIpPrefix,
        [parameter (Mandatory = $true)] [string] $SenderIpAddress,
        [parameter (Mandatory = $false)] [string] $SenderMacAddress
    )
    $Type = "NeighborDiscovery";
    $ndPolicy = @{
                TargetIpPrefix = $TargetIpPrefix;
                SenderIpAddress = $SenderIpAddress;
                SenderMacAddress = $SenderMacAddress;
    }
    $settings = @{
        Type = $Type;
        Settings = $ndPolicy;
    }
    New-HnsNetworkPolicy -NetworkId $NetworkId -Policies @($Settings)
}

function Remove-HnsNeighborDiscoveryPolicy
{
    param
    (
        [parameter (Mandatory = $true)] [Guid] $NetworkId,
        [parameter (Mandatory = $true)] [string] $TargetIpPrefix,
        [parameter (Mandatory = $true)] [string] $SenderIpAddress,
        [parameter (Mandatory = $false)] [string] $SenderMacAddress
    )
    $Type = "NeighborDiscovery";
    $ndPolicy = @{
                TargetIpPrefix = $TargetIpPrefix;
                SenderIpAddress = $SenderIpAddress;
                SenderMacAddress = $SenderMacAddress;
    }
    $settings = @{
        Type = $Type;
        Settings = $ndPolicy;
    }
    Remove-HnsNetworkPolicy -NetworkId $NetworkId -Policies @($Settings)
}

function New-HnsSubnet
{
    param
    (
        [parameter(Mandatory = $false)] [Guid] $NetworkId = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $Subnets
    )
    $requestType = [ModifyRequestType]::Add
    $resourceType = [NetworkResourceType]::Subnet
    Modify-HnsNetwork -Id $NetworkId -RequestType $requestType -ResourceType $resourceType -SubnetArray $Subnets
}

function Remove-HnsSubnet
{
    param
    (
        [parameter(Mandatory = $false)] [Guid] $NetworkId = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $Subnets
    )
    $requestType = [ModifyRequestType]::Remove
    $resourceType = [NetworkResourceType]::Subnet
    Modify-HnsNetwork -Id $NetworkId -RequestType $requestType -ResourceType $resourceType -SubnetArray $Subnets
}

function New-HnsIPSubnet
{
    param
    (
        [parameter(Mandatory = $false)] [Guid] $NetworkId = $null,
        [parameter(Mandatory = $false)] [Guid] $SubnetId = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $IPSubnets
    )
    $requestType = [ModifyRequestType]::Add
    $resourceType = [NetworkResourceType]::IPSubnet
    Modify-HnsNetwork -Id $NetworkId -RequestType $requestType -ResourceType $resourceType -SubnetId $SubnetId -IPSubnetArray $IPSubnets
}

function Remove-HnsIPSubnet
{
    param
    (
        [parameter(Mandatory = $false)] [Guid] $NetworkId = $null,
        [parameter(Mandatory = $false)] [Guid] $SubnetId = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $IPSubnets
    )
    $requestType = [ModifyRequestType]::Remove
    $resourceType = [NetworkResourceType]::IPSubnet
    Modify-HnsNetwork -Id $NetworkId -RequestType $requestType -ResourceType $resourceType -SubnetId $SubnetId -IPSubnetArray $IPSubnets
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
        [HashTable][parameter(Mandatory=$false)] $Settings,
        [HashTable[]][parameter(Mandatory=$false)] $PolicyArray,
        [HashTable[]][parameter(Mandatory=$false)] $SubnetArray,
        [parameter(Mandatory=$false)] $SubnetId,
        [HashTable[]][parameter(Mandatory=$false)] $IPSubnetArray
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

    if($SubnetArray)
    {
        $Subnets = @{
            Subnets = $SubnetArray;
        }
        $msettings += @{
            Settings = $Subnets;
        }
    }

    if($IPSubnetArray)
    {
        $IPSubnets = @{
            SubnetId = $SubnetId
            IpSubnets = $IPSubnetArray;
        }
        $msettings += @{
            Settings = $IPSubnets;
        }
    }

    return Modify-HnsGeneric -Id $Id -NativeMethods $NetworkNativeMethods -Settings $msettings
}
#########################################################################
# Endpoints
#########################################################################
Add-Type -TypeDefinition @"
    [System.Flags]
    public enum NatFlags
    {
        None = 0,
        LocalRoutedVip = 1,
        IPv6 = 2,
        ExternalPortReserved = 4,
    }
"@

function New-HnsEndpoint
{
    param
    (
        [parameter(Mandatory=$false, Position = 0)] [string] $JsonString = $null,
        [parameter(Mandatory = $true, Position = 0)] [Guid] $NetworkId,
        [parameter(Mandatory = $false)] [string] $Name,
        [parameter(Mandatory = $false)] [string] $IPAddress,
        [parameter(Mandatory = $false)] [uint16] $PrefixLength,
        [parameter(Mandatory = $false)] [string] $IPv6Address,
        [parameter(Mandatory = $false)] [uint16] $IPv6PrefixLength,
        [parameter(Mandatory = $false)] [string] $GatewayAddress,
        [parameter(Mandatory = $false)] [string] $GatewayAddressV6,
        [parameter(Mandatory = $false)] [string] $DNSServerList,
        [parameter(Mandatory = $false)] [string] $MacAddress,
        [parameter(Mandatory = $false)] [switch] $RemoteEndpoint,
        [parameter(Mandatory = $false)] [switch] $EnableOutboundNat,
        [HashTable][parameter(Mandatory=$false)] $OutboundNatPolicy, #  @ {"LocalRoutedVip" = true; "VIP" = ""; ExceptionList = ["", ""]}
        [HashTable][parameter(Mandatory=$false)] $OutboundNatPolicyV6, #  @ {"LocalRoutedVip" = true; "VIP" = ""; ExceptionList = ["", ""]}
        [parameter(Mandatory = $false)] [string[]] $OutboundNatExceptions,
        [parameter(Mandatory = $false)] [string[]] $RoutePrefixes, # Deprecate this. use RoutePolicies
        [HashTable[]][parameter(Mandatory=$false)] $RoutePolicies, #  @( @ {"DestinationPrefix" = ""; "NeedEncap" = true; "NextHop" = ""} )
        [HashTable][parameter(Mandatory=$false)] $InboundNatPolicy, #  @ {"InternalPort" = "80"; "ExternalPort" = "8080"}
        [HashTable][parameter(Mandatory=$false)] $InboundNatPolicyV6, #  @ {"InternalPort" = "80"; "ExternalPort" = "8080"}
        [HashTable][parameter(Mandatory=$false)] $PAPolicy, #  @ {"PA" = "1.2.3.4"; }
        [parameter(Mandatory = $false)] [switch] $UseInternalDns
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

            if ($IPAddress -Or $PrefixLength) {
                $IpConfiguration = @{
                }

                if ($IPAddress) {
                    $IpConfiguration.IpAddress = $IPAddress;
                }

                if ($PrefixLength) {
                    $IpConfiguration.PrefixLength = $PrefixLength;
                }
                $IpConfigurations += $IpConfiguration;
            }

            if ($GatewayAddress) {
                $Routes += @{ NextHop = $GatewayAddress; DestinationPrefix = "0.0.0.0/0"}
            }

            if ($IPv6Address -Or $IPv6PrefixLength) {
                $IpConfiguration = @{
                }

                if ($IPv6Address) {
                    $IpConfiguration.IpAddress = $IPv6Address;
                }

                if ($IPv6PrefixLength) {
                    $IpConfiguration.PrefixLength = $IPv6PrefixLength;
                }
                $IpConfigurations += $IpConfiguration;
            }

            if ($GatewayAddressV6) {
                $Routes += @{ NextHop = $GatewayAddressV6; DestinationPrefix = "::/0"}
            }

            $endpoint += @{IpConfigurations = $IpConfigurations}
            $endpoint += @{Routes = $Routes}

            if ($DNSServerList) {
                $list = $DNSServerList -split ","
                $endpoint += @{Dns = @{ ServerList = $list}}
            }

            [EndpointFlags]$Flags = [EndpointFlags]::None;

            if ($RemoteEndpoint.IsPresent) {
                $Flags = $Flags -bor [EndpointFlags]::RemoteEndpoint;
            }

            if ($UseInternalDns.IsPresent) {
                $Flags = $Flags -bor [EndpointFlags]::OverrideDNSServerOrder;
            }

            if($Flags -ne [EndpointFlags]::None)
            {
                $endpoint += @{Flags= $Flags;}
            }

            if ($EnableOutboundNat.IsPresent) {
                $Settings = @{}
                if ($OutboundNatExceptions) {
                    $ExceptionList = $null
                    foreach ($exp in $OutboundNatExceptions)
                    {
                        if(-not $exp.Contains(":"))
                        {
                            if($null -eq $ExceptionList)
                            {
                                $ExceptionList = @()
                            }

                            $ExceptionList += $exp
                        }
                    }
                    $Settings += @{Exceptions = $ExceptionList}
                }

                $endpoint.Policies +=  @{
                    Type = "OutBoundNAT";
                    Settings = $Settings;
                };

                if(-not [string]::IsNullOrEmpty($IPv6Address))
                {
                    $flags = [NatFlags]::Ipv6

                    $Settings = @{
                        Flags = $flags
                    }

                    if ($OutboundNatExceptions) {
                        $ExceptionList = $null
                        foreach ($exp in $OutboundNatExceptions)
                        {
                            if($exp.Contains(":"))
                            {
                                if($null -eq $ExceptionList)
                                {
                                    $ExceptionList = @()
                                }

                                $ExceptionList += $exp
                            }
                        }
                        $Settings += @{Exceptions = $ExceptionList}
                    }

                    $endpoint.Policies +=  @{
                        Type = "OutBoundNAT";
                        Settings = $Settings;
                    };
                }
            }

            if ($OutboundNatPolicy)
            {
                $natFlags = 0;
                if ($OutboundNatPolicy["LocalRoutedVip"])
                {
                    $natFlags = $natFlags -bor [NatFlags]::LocalRoutedVip
                }
                $settings = $OutboundNatPolicy
                $settings += @{
                    Flags = $natFlags;
                }

                $endpoint.Policies +=  @{
                    Type = "OutBoundNAT";
                    Settings = $settings;
                };
            }

            if ($OutboundNatPolicyV6)
            {
                $natFlags = [NatFlags]::Ipv6
                if ($OutboundNatPolicy["LocalRoutedVip"])
                {
                    $natFlags = $natFlags -bor [NatFlags]::LocalRoutedVip
                }
                $settings = $OutboundNatPolicy
                $settings += @{
                    Flags = $natFlags;
                }

                $endpoint.Policies +=  @{
                    Type = "OutBoundNAT";
                    Settings = $settings;
                };
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

                    $endpoint.Policies +=  @{
                        Type = "SDNRoute";
                        Settings = $rPolicy;
                    };
                }
            }

            # Deprecate this
            if ($RoutePrefixes)
            {
                foreach ($routeprefix in $RoutePrefixes) {
                    $rPolicy = @{
                        DestinationPrefix = $routeprefix;
                        NeedEncap = $true;
                    }
                    $endpoint.Policies +=  @{
                        Type = "SDNRoute";
                        Settings = $rPolicy;
                    };
                }
            }

            if ($InboundNatPolicy) {
                $natFlags = 0;
                if ($InboundNatPolicy["LocalRoutedVip"])
                {
                    $natFlags = $natFlags -bor [NatFlags]::LocalRoutedVip
                }

                if ($InboundNatPolicy["ExternalPortReserved"])
                {
                    $natFlags = $natFlags -bor [NatFlags]::ExternalPortReserved
                }

                $endpoint.Policies += @{
                    Type = "PortMapping";
                    Settings = @{
                        InternalPort = $InboundNatPolicy["InternalPort"];
                        ExternalPort = $InboundNatPolicy["ExternalPort"];
                        Flags = $natFlags;
                    };
                }
            }

            if ($InboundNatPolicyV6) {
                $natFlags = [NatFlags]::Ipv6
                if ($InboundNatPolicy["LocalRoutedVip"])
                {
                    $natFlags = $natFlags -bor [NatFlags]::LocalRoutedVip
                }

                if ($InboundNatPolicy["ExternalPortReserved"])
                {
                    $natFlags = $natFlags -bor [NatFlags]::ExternalPortReserved
                }

                $endpoint.Policies += @{
                    Type = "PortMapping";
                    Settings = @{
                        InternalPort = $InboundNatPolicy["InternalPort"];
                        ExternalPort = $InboundNatPolicy["ExternalPort"];
                        Flags = $natFlags;
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
function Add-HnsEndpointPolicy {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $Policies
    )
    $requestType = [ModifyRequestType]::Add
    $resourceType = [EndpointResourceType]::Policy
    foreach ($id in $Endpoints) {
        $null = Get-HnsEndpoint -Id $id -Version 2
        Modify-HnsEndpoint -Id $Id -RequestType $requestType -ResourceType $resourceType -PolicyArray $Policies
    }
}
function Remove-HnsEndpointPolicy {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null,
        [parameter(Mandatory = $false)] [HashTable[]] $Policies
    )
    $requestType = [ModifyRequestType]::Remove
    $resourceType = [EndpointResourceType]::Policy
    foreach ($id in $Endpoints) {
        $null = Get-HnsEndpoint -Id $id -Version 2
        Modify-HnsEndpoint -Id $Id -RequestType $requestType -ResourceType $resourceType -PolicyArray $Policies
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
        $null = Get-HnsEndpoint -Id $id -Version 2
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
    Update-HnsEndpointPolicy -Endpoints $Endpoints -Policies @($Settings)

}

function Remove-HnsProxyPolicy {
    param
    (
        [parameter(Mandatory = $false)] [Guid[]] $Endpoints = $null
    )

    Update-HnsEndpointPolicy -Endpoints $Endpoints -Policies @(@{})
}

function New-HnsSetPolicy {
    param
    (
        [parameter(Mandatory = $true)] [Guid] $NetworkId,
        [parameter(Mandatory = $true)] [string] $setId,
        [parameter(Mandatory = $true)] [string] $setName,
        [parameter(Mandatory = $true)] [int] $setType,
        [parameter(Mandatory = $true)] [string] $setValues
    )
    $Type = "SetPolicy"
    $SetPolicy = @{
        Id = $setId;
        Name = $setName;
        PolicyType = $setType;
        Values = $setValues;
    };

    $settings = @{
        Type = $Type;
        Settings = $SetPolicy;
    };

    New-HnsNetworkPolicy -NetworkId $networkId -Policies @($settings) 
}

function Update-HnsSetPolicy {
    param
    (
        [parameter(Mandatory = $true)] [Guid] $NetworkId,
        [parameter(Mandatory = $true)] [string] $setId,
        [parameter(Mandatory = $true)] [string] $setName,
        [parameter(Mandatory = $true)] [int] $setType,
        [parameter(Mandatory = $true)] [string] $setValues
    )
    $Type = "SetPolicy"
    $SetPolicy = @{
        Id = $setId;
        Name = $setName;
        PolicyType = $setType;
        Values = $setValues;
    };

    $settings = @{
        Type = $Type;
        Settings = $SetPolicy;
    };

    Update-HnsNetworkPolicy -NetworkId $networkId -Policies @($settings) 
}

function Remove-HnsSetPolicy {
    param
    (
        [parameter(Mandatory = $true)] [Guid] $NetworkId,
        [parameter(Mandatory = $true)] [string] $setId,
        [parameter(Mandatory = $true)] [string] $setName,
        [parameter(Mandatory = $true)] [int] $setType,
        [parameter(Mandatory = $true)] [string] $setValues
    )
    
    $Type = "SetPolicy"
    $SetPolicy = @{
        Id = $setId;
        Name = $setName;
        PolicyType = $setType;
        Values = $setValues;
    };

    $settings = @{
        Type = $Type;
        Settings = $SetPolicy;
    };

    Remove-HnsNetworkPolicy -NetworkId $NetworkId -Policies @($Settings)
}

function New-HnsL4ProxyPolicy {
    param
    (
        [parameter(Mandatory = $true)] [Guid] $NetworkId,
        [parameter(Mandatory = $false)] [string] $Destination,
        [parameter(Mandatory = $false)] [string] $DestinationPort,
        [parameter(Mandatory = $false)] [int] $Protocol,
        [parameter(Mandatory = $false)] [string] $ProxyDestination
    )
    
    $Type = "L4Proxy"
    $ProxyPolicy   = @{
        IP = $Destination;
        Port = $DestinationPort;
        Protocol = $Protocol;
        Destination = $ProxyDestination;
    };
        
    $settings = @{
        Type = $Type;
        Settings = $ProxyPolicy;
    };

    New-HnsNetworkPolicy -NetworkId $networkId -Policies @($settings)
}

function Remove-HnsL4ProxyPolicy {
    param
    (
        [parameter(Mandatory = $true)] [Guid] $NetworkId,
        [parameter(Mandatory = $false)] [string] $Destination,
        [parameter(Mandatory = $false)] [string] $DestinationPort,
        [parameter(Mandatory = $false)] [int] $Protocol,
        [parameter(Mandatory = $false)] [string] $ProxyDestination
    )
    
    $Type = "L4Proxy"
    $ProxyPolicy   = @{
        IP = $Destination;
        Port = $DestinationPort;
        Protocol = $Protocol;
        Destination = $ProxyDestination;
    };
        
    $settings = @{
        Type = $Type;
        Settings = $ProxyPolicy;
    };

    Remove-HnsNetworkPolicy -NetworkId $NetworkId -Policies @($Settings)
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
        Created,
        Bootstrapping,
        Synchronized,
        Paused,
        Desynchronized,
        Rehydrating,
        Degraded,
        Destroyed,
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


####   COPIED FROM V1 TO USE FOR KUBERNETES TESTS   ####

#########################################################################

function Get-VmComputeNativeMethods()
{
        $signature = @'
                     [DllImport("vmcompute.dll")]
                     public static extern void HNSCall([MarshalAs(UnmanagedType.LPWStr)] string method, [MarshalAs(UnmanagedType.LPWStr)] string path, [MarshalAs(UnmanagedType.LPWStr)] string request, [MarshalAs(UnmanagedType.LPWStr)] out string response);
'@

    # Compile into runtime type
    Add-Type -MemberDefinition $signature -Namespace VmCompute.HNSPrivate.PrivatePInvoke -Name NativeMethods -PassThru
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

    return Invoke-HnsEndpointRequest -Method POST -Data (ConvertTo-Json $request -Depth 10) -Action attach -Id $EndpointID
}

function Attach-HnsVMEndpoint
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
    return Invoke-HnsEndpointRequest -Method POST -Data (ConvertTo-Json $request -Depth 10) -Action attach -Id $EndpointID

}

function Attach-HnsEndpoint
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

    return Invoke-HnsEndpointRequest -Method POST -Data (ConvertTo-Json $request -Depth 10) -Action attach -Id $EndpointID
}

function Detach-HnsVMEndpoint
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $EndpointID
    )
    $request = @{
        SystemType  = "VirtualMachine";
    };

    return Invoke-HnsEndpointRequest -Method POST -Data (ConvertTo-Json $request -Depth 10) -Action detach -Id $EndpointID
}

function Detach-HnsHostEndpoint
{
    param
    (
        [parameter(Mandatory=$true)] [Guid] $EndpointID
    )
    $request = @{
        SystemType  = "Host";
    };

    return Invoke-HnsEndpointRequest -Method POST -Data (ConvertTo-Json $request -Depth 10) -Action detach -Id $EndpointID
}

function Detach-HnsEndpoint
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

    return Invoke-HnsEndpointRequest -Method POST -Data (ConvertTo-Json $request -Depth 10) -Action detach -Id $EndpointID
}

#########################################################################

function Invoke-HnsEndpointRequest
{
    param
    (
        [ValidateSet('GET', 'POST', 'DELETE')]
        [parameter(Mandatory=$true)] [string] $Method,
        [ValidateSet('attach', 'detach', 'detailed')]
        [parameter(Mandatory=$false)] [string] $Action = $null,
        [parameter(Mandatory=$false)] [string] $Data = $null,
        [parameter(Mandatory=$false)] [string] $Id = $null
    )
    return Invoke-HnsRequest -Method $Method -Type endpoints -Action $Action -Data $Data -Id $Id
}

#########################################################################

function Invoke-HnsRequest
{
    param
    (
        [ValidateSet('GET', 'POST', 'DELETE')]
        [parameter(Mandatory=$true)] [string] $Method,
        [ValidateSet('networks', 'endpoints', 'activities', 'policylists', 'endpointstats', 'plugins', 'namespaces', 'globals', 'endpointaddresses')]
        [parameter(Mandatory=$true)] [string] $Type,
        [parameter(Mandatory=$false)] [string] $Action = $null,
        [parameter(Mandatory=$false)] [string] $Data = $null,
        [parameter(Mandatory=$false)] [string] $Id = $null
    )

    $hnsPath = "/$Type"

    if ($id)
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
    Write-Verbose "Invoke-HnsRequest Type[$Type] Method[$Method] Path[$hnsPath] Data[$request]"

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


####   END COPIED FROM V1 TO USE FOR KUBERNETES TESTS   ####

#########################################################################

Export-ModuleMember -Function New-HnsNetwork
Export-ModuleMember -Function New-HnsIcsNetwork
Export-ModuleMember -Function Get-HnsNetwork
Export-ModuleMember -Function Remove-HnsNetwork
Export-ModuleMember -Function Modify-HnsNetwork
Export-ModuleMember -Function Update-HnsNetworkDNS
Export-ModuleMember -Function Update-HnsNetworkExtension
Export-ModuleMember -Function New-HnsRemoteSubnetRoutePolicy
Export-ModuleMember -Function Remove-HnsRemoteSubnetRoutePolicy
Export-ModuleMember -Function New-HnsHostRoutePolicy
Export-ModuleMember -Function Remove-HnsHostRoutePolicy
Export-ModuleMember -Function New-HnsSubnet
Export-ModuleMember -Function Remove-HnsSubnet
Export-ModuleMember -Function New-HnsIPSubnet
Export-ModuleMember -Function Remove-HnsIPSubnet

Export-ModuleMember -Function New-HnsEndpoint
Export-ModuleMember -Function New-HnsRemoteEndpoint
Export-ModuleMember -Function Get-HnsEndpoint
Export-ModuleMember -Function Modify-HnsEndpoint
Export-ModuleMember -Function Update-HnsEndpointPolicy
Export-ModuleMember -Function Add-HnsEndpointPolicy
Export-ModuleMember -Function Remove-HnsEndpointPolicy
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

Export-ModuleMember -Function New-HnsRoute
Export-ModuleMember -Function Get-HnsRoute
Export-ModuleMember -Function Remove-HnsRoute

Export-ModuleMember -Function New-HnsProxyPolicy
Export-ModuleMember -Function Remove-HnsProxyPolicy

Export-ModuleMember -Function Get-HnsGuestNetworkService
Export-ModuleMember -Function Modify-HnsGuestNetworkService
Export-ModuleMember -Function Modify-HnsGuestNetworkServiceState


Export-ModuleMember -Function Attach-HnsHostEndpoint
Export-ModuleMember -Function Attach-HnsVMEndpoint
Export-ModuleMember -Function Attach-HnsEndpoint
Export-ModuleMember -Function Detach-HnsHostEndpoint
Export-ModuleMember -Function Detach-HnsVMEndpoint
Export-ModuleMember -Function Detach-HnsEndpoint

Export-ModuleMember -Function Invoke-HnsRequest

Export-ModuleMember -Function New-HnsL4ProxyPolicy
Export-ModuleMember -Function Remove-HnsL4ProxyPolicy

Export-ModuleMember -Function New-HnsSetPolicy
Export-ModuleMember -Function Remove-HnsSetPolicy
Export-ModuleMember -Function Update-HnsSetPolicy

Export-ModuleMember -Function New-HnsNeighborDiscoveryPolicy
Export-ModuleMember -Function Remove-HnsNeighborDiscoveryPolicy