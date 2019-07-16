Param(
    [parameter(Mandatory = $true)] $ManagementIP,
    [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] $NetworkMode="l2bridge",
    [parameter(Mandatory = $false)] $ClusterCIDR="10.244.0.0/16",
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $LogDir="C:\k",
    [parameter(Mandatory = $false)] $KubeletSvc="kubelet",
    [parameter(Mandatory = $false)] $KubeProxySvc="kube-proxy",
    [parameter(Mandatory = $false)] $KubeletFeatureGates="",
    [parameter(Mandatory = $false)] $NetworkName="cbr0",
    [parameter(Mandatory = $false)] $FlanneldSvc="flanneld"
)

$helper = "c:\k\helper.psm1"
ipmo $helper

$Hostname=$(hostname).ToLower()
$NetworkMode = $NetworkMode.ToLower()
cd c:\k

# register flanneld
CleanupOldNetwork -NetworkName $NetworkName

.\nssm.exe install $FlanneldSvc C:\flannel\flanneld.exe
.\nssm.exe set $FlanneldSvc AppParameters --kubeconfig-file=c:\k\config --iface=$ManagementIP --ip-masq=1 --kube-subnet-mgr=1
.\nssm.exe set $FlanneldSvc AppEnvironmentExtra NODE_NAME=$Hostname
.\nssm.exe set $FlanneldSvc AppDirectory C:\flannel
.\nssm.exe start $FlanneldSvc

WaitForNetwork -NetworkName $NetworkName


Start-Sleep 5

if ($NetworkMode -eq "overlay")
{
    GetSourceVip -ipAddress $ManagementIP -NetworkName $NetworkName
}


# register kubelet
.\nssm.exe install $KubeletSvc C:\k\kubelet.exe

$kubeletArgs = @(
    "--hostname-override=$(hostname)"
    '--v=6'
    '--pod-infra-container-image=kubeletwin/pause'
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

.\nssm.exe set $KubeletSvc AppParameters $kubeletArgs
.\nssm.exe set $KubeletSvc AppDirectory C:\k
.\nssm.exe start $KubeletSvc

Start-Sleep 5

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

Start-Sleep 5