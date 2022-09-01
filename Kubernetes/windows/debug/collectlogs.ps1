#Requires -RunAsAdministrator

Param(
    [parameter(Mandatory = $false)] [string] $Network = "L2Bridge",
    [parameter(Mandatory = $false)] [ValidateSet(1,2)] [int] $HnsSchemaVersion = 2
)

$GithubSDNRepository = 'Microsoft/SDN'
if ((Test-Path env:GITHUB_SDN_REPOSITORY) -and ($env:GITHUB_SDN_REPOSITORY -ne ''))
{
    $GithubSDNRepository = $env:GITHUB_SDN_REPOSITORY
}

$BaseDir = "c:\k\debug"
md $BaseDir -ErrorAction Ignore

$helper = "$BaseDir\helper.psm1"
if (!(Test-Path $helper))
{
    Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/helper.psm1" -OutFile $BaseDir\helper.psm1
}
ipmo $helper -Function DownloadFile

DownloadFile -Url  "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/dumpVfpPolicies.ps1" -Destination $BaseDir\dumpVfpPolicies.ps1
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/hns.v2.psm1" -Destination $BaseDir\hns.v2.psm1
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/starthnstrace.cmd" -Destination $BaseDir\starthnstrace.cmd
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/starthnstrace.ps1" -Destination $BaseDir\starthnstrace.ps1
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/startpacketcapture.cmd" -Destination $BaseDir\startpacketcapture.cmd
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/startpacketcapture.ps1" -Destination $BaseDir\startpacketcapture.ps1
DownloadFile -Url  "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/stoppacketcapture.cmd" -Destination $BaseDir\stoppacketcapture.cmd
DownloadFile -Url  "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/portReservationTest.ps1" -Destination $BaseDir\portReservationTest.ps1

ipmo $BaseDir\hns.v2.psm1 -Force

$ScriptPath = Split-Path $MyInvocation.MyCommand.Path

$outDir = [io.Path]::Combine($ScriptPath, [io.Path]::GetRandomFileName())
md $outDir
pushd 
cd $outDir

# V1
if($HnsSchemaVersion -eq 1)
{
    # V1 Networks
    Get-HnsNetwork -Version 1 | Select Name, Type, Id, @{Name="AddressPrefix"; Expression={$_.Subnets.AddressPrefix}} > network.txt

    # V1 Endpoints
    Get-HnsEndpoint -Version 1 | Select IpAddress, MacAddress, IsRemoteEndpoint, State > endpoint.txt

    # V1 Namespaces
    Get-HnsNamespace -Version 1 `
    | Select ID, `
    CompartmentId, `
    CompartmentGuid, `
    IsDefault, @{Name="EndpointID"; Expression={$_.ResourceList.Data.Id}} > namespaces.txt
}
# V2
else
{
    # V2 Networks
    Get-HnsNetwork -Version 2 `
    | Select Name, Type, Id,`
    @{Name="AddressPrefix"; Expression={$_.Ipams.Subnets.IpAddressPrefix}}` > network.txt

    # V2 Endpoints
    Get-HnsEndpoint -Version 2 `
    | Select @{Name="IpAddress"; Expression={$_.IpConfigurations.IpAddress}}, `
    MacAddress, `
    @{Name="IsRemoteEndpoint"; Expression={(Get-HNSEndpoint -Version 1 -Id $_.ID).IsRemoteEndpoint}}, `
    @{Name="State"; Expression={(Get-HNSEndpoint -Version 1 -Id $_.ID).State}} > endpoint.txt
    
    # V2 Namespaces
    Get-HnsNamespace -Version 2 `
    | Select ID, `
    @{Name="CompartmentID"; Expression={$_.NamespaceId}}, `
    @{Name="CompartmentGuid"; Expression={$_.NamespaceGuid}}, `
    Type, @{Name="EndpointID"; Expression={$_.Resources.Data.Id}} > namespaces.txt
}

# Networks
Get-hnsnetwork -Version $HnsSchemaVersion | Convertto-json -Depth 20 >> network.txt
Get-hnsnetwork -Version $HnsSchemaVersion | % { Get-HnsNetwork -Id $_.ID -Detailed } | Convertto-json -Depth 20 >> networkdetailed.txt

# Endpoints
Get-hnsendpoint -Version $HnsSchemaVersion | Convertto-json -Depth 20 >> endpoint.txt

# Load Balancers
Get-HnsLoadBalancer -Version $HnsSchemaVersion | Convertto-json -Depth 20 > policy.txt

# Namespaces
Get-HnsNamespace -Version $HnsSchemaVersion | Convertto-json -Depth 20 >> namespaces.txt

vfpctrl.exe /list-vmswitch-port > ports.txt
powershell $BaseDir\dumpVfpPolicies.ps1 -switchName $Network -outfile vfpOutput.txt

# Loop through ports.txt file
$ports = @()
foreach($line in (Get-Content ports.txt)){
    $nline = $line.Split(":")
    if ($nline[0].contains('Port name'))
    {
        $ports += $nline[1]
    }
}

# For each port, we want to call get-port-counter
foreach($port in $ports)
{
    "Get-port-counter for port: $port" >> ports.txt
    vfpctrl /port $port.trim() /get-port-counter >> ports.txt
}
ipconfig /allcompartments /all > ip.txt
Get-NetIPAddress -IncludeAllCompartments >> ip.txt
Get-NetIPInterface -IncludeAllCompartments >> ip.txt
route print > routes.txt
Get-NetRoute -IncludeAllCompartments >> routes.txt
netsh int ipv4 sh int > mtu.txt
nvspinfo -a -i -h -D -p -d -m -q > nvspinfo.txt
nmscrub -a -n -t > nmscrub.txt
nmbind > nmbind.txt
arp -a > arp.txt

sc.exe queryex          > scqueryex.txt
sc.exe qc hns          >> scqueryex.txt
sc.exe qc vfpext       >> scqueryex.txt
sc.exe qc dnscache     >> scqueryex.txt
sc.exe qc iphlpsvc     >> scqueryex.txt
sc.exe qc BFE          >> scqueryex.txt
sc.exe qc Dhcp         >> scqueryex.txt
sc.exe qc hvsics       >> scqueryex.txt
sc.exe qc NetSetupSvc  >> scqueryex.txt
sc.exe qc mpssvc       >> scqueryex.txt
sc.exe qc nvagent      >> scqueryex.txt
sc.exe qc nsi          >> scqueryex.txt
sc.exe qc vmcompute    >> scqueryex.txt
sc.exe qc SharedAccess >> scqueryex.txt
sc.exe qc CmService    >> scqueryex.txt
sc.exe qc vmms         >> scqueryex.txt

Get-NetNeighbor -IncludeAllCompartments >> arp.txt

Get-NetAdapter -IncludeHidden >> netadapter.txt

New-Item -Path adapters -ItemType Directory
$arrInvalidChars = [System.IO.Path]::GetInvalidFileNameChars()
$invalidChars = [RegEx]::Escape(-join $arrInvalidChars)

Get-NetAdapter -IncludeHidden  | foreach {
    $ifindex=$_.IfIndex; 
    $ifName=$_.Name;
    $fileName="${ifName}_int.txt";
    $fileName=[RegEx]::Replace($fileName, "[$invalidChars]", ' ');
    netsh int ipv4 sh int $ifindex | Out-File -FilePath "adapters\$fileName" -Encoding ascii;
    $_ | FL * | Out-File -Append -FilePath "adapters\$fileName" -Encoding ascii
    }

Get-NetFirewallRule -PolicyStore ActiveStore >> firewall.txt

New-Item -Path wfp -ItemType Directory
cd wfp
netsh wfp show netevents
netsh wfp show state
netsh wfp show filters
cd $outDir

$res = Get-Command hnsdiag.exe -ErrorAction SilentlyContinue
if ($res)
{
    hnsdiag list all -d > hnsdiag.txt
}
hcsdiag list  > hcsdiag.txt

$res = Get-Command ctr.exe -ErrorAction SilentlyContinue
if ($res)
{
    ctr -n "k8s.io" c ls > containers.txt
}

function CountAvailableEphemeralPorts([string]$protocol = "TCP", [uint32]$portRangeSize = 64) {
    # First, remove all the text bells and whistle (plain text, table headers, dashes, empty lines, ...) from netsh output 
    $tcpRanges = (netsh int ipv4 sh excludedportrange $protocol) -replace "[^0-9,\ ]",'' | ? {$_.trim() -ne "" }
 
    # Then, remove any extra space characters. Only capture the numbers representing the beginning and end of range
    $tcpRangesArray = $tcpRanges -replace "\s+(\d+)\s+(\d+)\s+",'$1,$2' | ConvertFrom-String -Delimiter ","

    # Extract the ephemeral ports ranges
    $EphemeralPortRange = (netsh int ipv4 sh dynamicportrange $protocol) -replace "[^0-9]",'' | ? {$_.trim() -ne "" }
    $EphemeralPortStart = [Convert]::ToUInt32($EphemeralPortRange[0])
    $EphemeralPortEnd = $EphemeralPortStart + [Convert]::ToUInt32($EphemeralPortRange[1]) - 1

    # Find the external interface
    $externalInterfaceIdx = (Get-NetRoute -DestinationPrefix "0.0.0.0/0")[0].InterfaceIndex
    $hostIP = (Get-NetIPConfiguration -ifIndex $externalInterfaceIdx).IPv4Address.IPAddress

    # Extract the used TCP ports from the external interface
    $usedTcpPorts  = (Get-NetTCPConnection -LocalAddress $hostIP -ErrorAction Ignore).LocalPort
    $usedTcpPorts | % { $tcpRangesArray += [pscustomobject]@{P1 = $_; P2 = $_} }

    # Extract the used TCP ports from the 0.0.0.0 interface
    $usedTcpGlobalPorts = (Get-NetTCPConnection -LocalAddress "0.0.0.0" -ErrorAction Ignore).LocalPort
    $usedTcpGlobalPorts | % { $tcpRangesArray += [pscustomobject]@{P1 = $_; P2 = $_} }
    # Sort the list and remove duplicates
    $tcpRangesArray = ($tcpRangesArray | Sort-Object { $_.P1 } -Unique)

    $tcpRangesList = New-Object System.Collections.ArrayList($null)
    $tcpRangesList.AddRange($tcpRangesArray)

    # Remove overlapping ranges
    for ($i = $tcpRangesList.P1.Length - 2; $i -gt 0 ; $i--) { 
        if ($tcpRangesList[$i].P2 -gt $tcpRangesList[$i+1].P1 ) { 
            Write-Host "Removing $($tcpRangesList[$i+1])"
            $tcpRangesList.Remove($tcpRangesList[$i+1])
            $i++
        } 
    }

    # Remove the non-ephemeral port reservations from the list
    $filteredTcpRangeArray = $tcpRangesList | ? { $_.P1 -ge $EphemeralPortStart }
    $filteredTcpRangeArray = $filteredTcpRangeArray | ? { $_.P2 -le $EphemeralPortEnd }
    
    if ($filteredTcpRangeArray -eq $null) {
        $freeRanges = @($EphemeralPortRange[1])
    } else {
        $freeRanges = @()
        # The first free range goes from $EphemeralPortStart to the beginning of the first reserved range
        $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[0].P1) - $EphemeralPortStart)

        for ($i = 1; $i -lt $filteredTcpRangeArray.length; $i++) {
            # Subsequent free ranges go from the end of the previous reserved range to the beginning of the current reserved range
            $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[$i].P1) - [Convert]::ToUInt32($filteredTcpRangeArray[$i-1].P2) - 1)
        }

        # The last free range goes from the end of the last reserved range to $EphemeralPortEnd
        $freeRanges += ($EphemeralPortEnd - [Convert]::ToUInt32($filteredTcpRangeArray[$filteredTcpRangeArray.length - 1].P2))
    }
    
    # Count the number of available free ranges
    [uint32]$freeRangesCount = 0
    ($freeRanges | % { $freeRangesCount += [Math]::Floor($_ / $portRangeSize) } )

    return $freeRangesCount
}

$availableRangesFor64PortChunks = CountAvailableEphemeralPorts

if ($availableRangesFor64PortChunks -le 0) {
    echo "ERROR: Running out of ephemeral ports. The ephemeral ports range doesn't have enough resources to allow allocating 64 contiguous TCP ports." > reservedports.txt
} else {
    # There is unfortunately no exact way to calculate the ephemeral port ranges availability. 
    # The calculation done in this script gives a very coarse estimate that may yield overly optimistic reasults on some systems.
    # Use this data with caution.
    echo "Rough estimation of the ephemeral port availability: up to $availableRangesFor64PortChunks allocations of 64 contiguous TCP ports may be possible" > reservedports.txt
}

# The following scripts attempts to reserve a few ranges of 64 ephemeral ports. 
# Results produced by this test can accurately tell whether a system has room for reserving 64 contiguous port pools or not.
& "$BaseDir\PortReservationTest.ps1" >> reservedports.txt

netsh int ipv4 sh excludedportrange TCP > excludedportrange.txt
netsh int ipv4 sh excludedportrange UDP >> excludedportrange.txt
netsh int ipv4 sh dynamicportrange TCP > dynamicportrange.txt
netsh int ipv4 sh dynamicportrange UDP >> dynamicportrange.txt
netsh int ipv4 sh tcpconnections > tcpconnections.txt

$ver = [System.Environment]::OSVersion
$hotFix = Get-HotFix

$ver.ToString() > winver.txt
"`n`n" >> winver.txt

if ($hotFix -ne $null)
{
    $hotFix >> winver.txt
} else {
    "<No hotfix>" >> winver.txt
}

# Copy the Windows event logs
New-Item -Path winevt -ItemType Directory
Copy-Item "$env:SystemDrive\Windows\System32\Winevt\Logs\Application.evtx" -Destination winevt
Copy-Item "$env:SystemDrive\Windows\System32\Winevt\Logs\System.evtx" -Destination winevt
Copy-Item "$env:SystemDrive\Windows\System32\Winevt\Logs\\Microsoft-Windows-Hyper-V*.evtx" -Destination winevt
Copy-Item "$env:SystemDrive\Windows\System32\Winevt\Logs\\Microsoft-Windows-Host-Network-Service*.evtx" -Destination winevt
Copy-Item "$env:SystemDrive\Windows\System32\Winevt\Logs\\Microsoft-Windows-Hyper-V-Compute-Admin*.evtx" -Destination winevt
Copy-Item "$env:SystemDrive\Windows\System32\Winevt\Logs\\Microsoft-Windows-Hyper-V-Compute-Operational*.evtx" -Destination winevt
Copy-Item "$env:SystemDrive\Windows\System32\Winevt\Logs\\Microsoft-Windows-Hyper-V-Worker-Admin*.evtx" -Destination winevt
Copy-Item "$env:SystemDrive\Windows\System32\Winevt\Logs\Microsoft-Windows-Hyper-V-Worker-Operational*.evtx" -Destination winevt

New-Item -Path logs -ItemType Directory
Copy-Item "$env:SystemDrive\Windows\logs\NetSetup" -Destination logs -Recurse
Copy-Item "$env:SystemDrive\Windows\logs\dism" -Destination logs -Recurse
Copy-Item "$env:SystemDrive\Windows\logs\cbs" -Destination logs -Recurse

popd
Write-Host "Logs are available at $outDir"
