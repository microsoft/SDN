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
Get-hnsnetwork | Convertto-json -Depth 20 >> network.txt

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

popd
Write-Host "Logs are available at $outDir"
