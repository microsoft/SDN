Param(
    [parameter(Mandatory = $false)] [string] $Network = "L2Bridge"
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
ipmo $helper

DownloadFile -Url  "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/dumpVfpPolicies.ps1" -Destination $BaseDir\dumpVfpPolicies.ps1
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/hns.psm1" -Destination $BaseDir\hns.psm1
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/starthnstrace.cmd" -Destination $BaseDir\starthnstrace.cmd
DownloadFile -Url "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/startpacketcapture.cmd" -Destination $BaseDir\startpacketcapture.cmd
DownloadFile -Url  "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/debug/stoppacketcapture.cmd" -Destination $BaseDir\stoppacketcapture.cmd

ipmo $BaseDir\hns.psm1

$ScriptPath = Split-Path $MyInvocation.MyCommand.Path

$outDir = [io.Path]::Combine($ScriptPath, [io.Path]::GetRandomFileName())
md $outDir
pushd 
cd $outDir

Get-HnsNetwork | Select Name, Type, Id, AddressPrefix > network.txt
Get-hnsnetwork | % { Get-HnsNetwork -Id $_.ID -Detailed } | Convertto-json -Depth 20 >> network.txt

Get-HnsEndpoint | Select IpAddress, MacAddress, IsRemoteEndpoint, State > endpoint.txt
Get-hnsendpoint | Convertto-json -Depth 20 >> endpoint.txt

Get-hnspolicylist | Convertto-json -Depth 20 > policy.txt

vfpctrl.exe /list-vmswitch-port > ports.txt
powershell $BaseDir\dumpVfpPolicies.ps1 -switchName $Network -outfile vfpOutput.txt

ipconfig /allcompartments /all > ip.txt
route print > routes.txt
netsh int ipv4 sh int > mtu.txt
nvspinfo -a -i -h -D -p -d -m -q > nvspinfo.txt
nmscrub -a -n -t > nmscrub.txt
arp -a > arp.txt
get-netadapter  | foreach {$ifindex=$_.IfIndex; $ifName=$_.Name; netsh int ipv4 sh int $ifindex | Out-File  -FilePath "${ifName}_int.txt" -Encoding ascii}

$res = Get-Command hnsdiag.exe -ErrorAction SilentlyContinue
if ($res)
{
    hnsdiag list all -d > hnsdiag.txt
}
hcsdiag list  > hcsdiag.txt

$res = Get-Command docker.exe -ErrorAction SilentlyContinue
if ($res)
{
    docker ps -a > docker.txt
}

function CountAvailableEphemeralPorts([string]$portocol = "TCP", [uint32]$portRangeSize = 64) {
    # First, remove all the text bells and whistle (plain text, table headers, dashes, empty lines, ...) from netsh output 
    $tcpRanges = (netsh int ipv4 sh excludedportrange $portocol) -replace "[^0-9,\ ]",'' | ? {$_.trim() -ne "" }
 
    # Then, remove any extra space characters. Only capture the numbers representing the beginning and end of range
    $tcpRangesArray = $tcpRanges -replace "\s+(\d+)\s+(\d+)\s+",'$1,$2' | ConvertFrom-String -Delimiter ","

    # Extract the ephemeral ports ranges
    $EphemeralPortRange = (netsh int ipv4 sh dynamicportrange $portocol) -replace "[^0-9]",'' | ? {$_.trim() -ne "" }
    $EphemeralPortStart = [Convert]::ToUInt32($EphemeralPortRange[0])
    $EphemeralPortEnd = $EphemeralPortStart + [Convert]::ToUInt32($EphemeralPortRange[1]) - 1

    # Remove the non-ephemeral port reservations from the list
    $filteredTcpRangeArray = $tcpRangesArray | ? { $_.P1 -ge $EphemeralPortStart }
    $filteredTcpRangeArray = $filteredTcpRangeArray | ? { $_.P2 -le $EphemeralPortEnd }

    $freeRanges = @()
    # The first free range goes from $EphemeralPortStart to the beginning of the first reserved range
    $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[0].P1) - $EphemeralPortStart)

    for ($i = 1; $i -lt $filteredTcpRangeArray.length; $i++) {
        # Subsequent free ranges go from the end of the previous reserved range to the beginning of the current reserved range
        $freeRanges += ([Convert]::ToUInt32($filteredTcpRangeArray[$i].P1) - [Convert]::ToUInt32($filteredTcpRangeArray[$i-1].P2) - 1)
    }

    # The last free range goes from the end of the last reserved range to $EphemeralPortEnd
    $freeRanges += ($EphemeralPortEnd - [Convert]::ToUInt32($filteredTcpRangeArray[$filteredTcpRangeArray.length - 1].P2) - 1)
    
    # Count the number of available free ranges
    [uint32]$freeRangesCount = 0
    ($freeRanges | % { $freeRangesCount += [UInt32]($_ / $portRangeSize) } )

    return $freeRangesCount
}

$availableRangesFor64PortChunks = CountAvailableEphemeralPorts

if ($availableRangesFor64PortChunks -le 0) {
    echo "ERROR: Running out of ephemeral ports. The ephemeral ports range doesn't have enough resources to allow allocating 64 contiguous TCP ports." > reservedports.txt
} else {
    echo "The ephemeral port range still has room for making up to $availableRangesFor64PortChunks allocations of 64 contiguous TCP ports" > reservedports.txt
}

netsh int ipv4 sh excludedportrange TCP >> reservedports.txt
netsh int ipv4 sh excludedportrange UDP >> reservedports.txt
netsh int ipv4 sh dynamicportrange TCP >> reservedports.txt
netsh int ipv4 sh dynamicportrange UDP >> reservedports.txt


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

popd
Write-Host "Logs are available at $outDir"
