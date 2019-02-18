Param(
    [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] [parameter(Mandatory = $true)] $NetworkMode,
    [parameter(Mandatory = $true)] $ManagementIP,
    [parameter(Mandatory = $false)] $ClusterCIDR="10.244.0.0/16",
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $LogDir="C:\k",
    [parameter(Mandatory = $false)] $KubeletSvc="kubelet",
    [parameter(Mandatory = $false)] $KubeProxySvc="kube-proxy",
    [parameter(Mandatory = $false)] $FlanneldSvc="flanneld"
)

$Hostname=$(hostname).ToLower()
$NetworkMode = $NetworkMode.ToLower()

# register flanneld
nssm install $FlanneldSvc C:\flannel\flanneld.exe
nssm set $FlanneldSvc AppParameters --kubeconfig-file=c:\k\config --iface=$ManagementIP --ip-masq=1 --kube-subnet-mgr=1
nssm set $FlanneldSvc AppEnvironmentExtra NODE_NAME=$Hostname
nssm set $FlanneldSvc AppDirectory C:\flannel
nssm start $FlanneldSvc

# register kubelet
nssm install $KubeletSvc C:\k\kubelet.exe
nssm set $KubeletSvc AppParameters --hostname-override=$Hostname --v=6 --pod-infra-container-image=kubeletwin/pause --resolv-conf="" --allow-privileged=true --enable-debugging-handlers --cluster-dns=$KubeDnsServiceIP --cluster-domain=cluster.local --kubeconfig=c:\k\config --hairpin-mode=promiscuous-bridge --image-pull-progress-deadline=20m --cgroups-per-qos=false  --log-dir=$LogDir --logtostderr=false --enforce-node-allocatable="" --network-plugin=cni --cni-bin-dir=c:\k\cni --cni-conf-dir=c:\k\cni\config
nssm set $KubeletSvc AppDirectory C:\k
nssm start $KubeletSvc

# register kube-proxy
nssm install $KubeProxySvc C:\k\kube-proxy.exe
nssm set $KubeProxySvc AppDirectory c:\k

if ($NetworkMode -eq "l2bridge")
{
    nssm set $KubeProxySvc AppParameters --v=4 --proxy-mode=kernelspace --hostname-override=$Hostname --kubeconfig=c:\k\config --network-name=cbr0 --enable-dsr=false --cluster-cidr=$ClusterCIDR --log-dir=$LogDir --logtostderr=false
}
elseif ($NetworkMode -eq "overlay")
{
    if((Test-Path c:/k/sourceVip.json)) 
    {
        $sourceVipJSON = Get-Content sourceVip.json | ConvertFrom-Json 
        $sourceVip = $sourceVipJSON.ip4.ip.Split("/")[0]
    }
    nssm set $KubeProxySvc AppParameters --v=4 --proxy-mode=kernelspace --feature-gates="WinOverlay=true" --hostname-override=$Hostname --kubeconfig=c:\k\config --network-name=vxlan0 --source-vip=$sourceVip --enable-dsr=false --cluster-cidr=$ClusterCIDR --log-dir=$LogDir --logtostderr=false
}
nssm set $KubeProxySvc DependOnService $KubeletSvc
nssm start $KubeProxySvc