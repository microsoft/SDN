Param(
    [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] [parameter(Mandatory = $true)] $NetworkMode,
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $LogDir = "C:\k",
    [parameter(Mandatory = $false)] $KubeletFeatureGates = "",
    [switch] $RegisterOnly
)

$GithubSDNRepository = 'Microsoft/SDN'
if ((Test-Path env:GITHUB_SDN_REPOSITORY) -and ($env:GITHUB_SDN_REPOSITORY -ne ''))
{
    $GithubSDNRepository = $env:GITHUB_SDN_REPOSITORY
}

$helper = "c:\k\helper.psm1"
if (!(Test-Path $helper))
{
    Start-BitsTransfer "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/helper.psm1" -Destination c:\k\helper.psm1
}
ipmo $helper

if ($RegisterOnly.IsPresent)
{
    RegisterNode
    exit
}

$kubeletArgs = @(
    "--hostname-override=$(hostname)"
    '--v=6'
    '--pod-infra-container-image=mcr.microsoft.com/k8s/core/pause:1.0.0'
    '--resolv-conf=""'
    '--allow-privileged=true'
    '--enable-debugging-handlers'
    "--cluster-dns=$KubeDnsServiceIp"
    '--cluster-domain=cluster.local'
    '--kubeconfig=c:\k\config'
    '--hairpin-mode=promiscuous-bridge'
    '--image-pull-progress-deadline=20m'
    '--cgroups-per-qos=false'
    "--log-dir=$LogDir"
    '--logtostderr=false'
    '--enforce-node-allocatable=""'
    '--network-plugin=cni'
    '--cni-bin-dir="c:\k\cni"'
    '--cni-conf-dir="c:\k\cni\config"'
    "--node-ip=$(Get-MgmtIpAddress)"
)

if ($KubeletFeatureGates -ne "")
{
    $kubeletArgs += "--feature-gates=$KubeletFeatureGates"
}

& c:\k\kubelet.exe $kubeletArgs
