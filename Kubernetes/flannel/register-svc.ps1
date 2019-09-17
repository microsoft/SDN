Param(
    [parameter(Mandatory = $true)] $ManagementIP,
    [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] $NetworkMode="l2bridge",
    [parameter(Mandatory = $false)] $ClusterCIDR="10.244.0.0/16",
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $LogDir="C:\k",
    [parameter(Mandatory = $false)] $KubeletSvc="kubelet",
    [parameter(Mandatory = $false)] $KubeProxySvc="kube-proxy",
    [parameter(Mandatory = $false)] $FlanneldSvc="flanneld"
)

$GithubSDNRepository = 'Microsoft/SDN'
if ((Test-Path env:GITHUB_SDN_REPOSITORY) -and ($env:GITHUB_SDN_REPOSITORY -ne ''))
{
    $GithubSDNRepository = $env:GITHUB_SDN_REPOSITORY
}

$helper = 'c:\k\helper.psm1'
if (!(Test-Path $helper))
{
    Start-BitsTransfer "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/helper.psm1" -Destination c:\k\helper.psm1
}
ipmo $helper

$Hostname=$(hostname).ToLower()
$NetworkMode = $NetworkMode.ToLower()
cd c:\k

# register flanneld
.\nssm.exe install $FlanneldSvc C:\flannel\flanneld.exe
.\nssm.exe set $FlanneldSvc AppParameters --kubeconfig-file=c:\k\config --iface=$ManagementIP --ip-masq=1 --kube-subnet-mgr=1
.\nssm.exe set $FlanneldSvc AppEnvironmentExtra NODE_NAME=$Hostname
.\nssm.exe set $FlanneldSvc AppDirectory C:\flannel
.\nssm.exe start $FlanneldSvc

# register kubelet
.\nssm.exe install $KubeletSvc C:\k\kubelet.exe
$kubeletOptions = Kubelet-Options $KubeDnsServiceIp $LogDir
$nssmArgs = @(
    'set'
    $KubeletSvc
    'AppParameters'
) + $kubeletOptions.Options
& .\nssm.exe $nssmArgs
.\nssm.exe set $KubeletSvc AppDirectory C:\k
.\nssm.exe start $KubeletSvc

# register kube-proxy
.\nssm.exe install $KubeProxySvc C:\k\kube-proxy.exe
.\nssm.exe set $KubeProxySvc AppDirectory c:\k

if ($NetworkMode -eq "l2bridge")
{
    .\nssm.exe set $KubeProxySvc AppEnvironmentExtra KUBE_NETWORK=cbr0
    .\nssm.exe set $KubeProxySvc AppParameters --v=4 --proxy-mode=kernelspace --hostname-override=$Hostname --kubeconfig=c:\k\config --cluster-cidr=$ClusterCIDR --log-dir=$LogDir --logtostderr=false
}
elseif ($NetworkMode -eq "overlay")
{
    if((Test-Path c:/k/sourceVip.json)) 
    {
        $sourceVipJSON = Get-Content sourceVip.json | ConvertFrom-Json 
        $sourceVip = $sourceVipJSON.ip4.ip.Split("/")[0]
    }
    .\nssm.exe set $KubeProxySvc AppParameters --v=4 --proxy-mode=kernelspace --feature-gates="WinOverlay=true" --hostname-override=$Hostname --kubeconfig=c:\k\config --network-name=vxlan0 --source-vip=$sourceVip --enable-dsr=false --cluster-cidr=$ClusterCIDR --log-dir=$LogDir --logtostderr=false
}
.\nssm.exe set $KubeProxySvc DependOnService $KubeletSvc
.\nssm.exe start $KubeProxySvc