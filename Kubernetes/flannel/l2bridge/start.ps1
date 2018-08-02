Param(
    [parameter(Mandatory = $true)] $ClusterCIDR,
    [parameter(Mandatory = $true)] $ManagementIP,
    [parameter(Mandatory = $true)] $KubeDnsServiceIP,
    [parameter(Mandatory = $true)] $ServiceCIDR,
    [ValidateSet("process", "hyperv")] $IsolationType = "process"
)

function DownloadFlannelBinaries()
{
    md c:\flannel -ErrorAction Ignore
    DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/flanneld.exe" -Destination c:\flannel\flanneld.exe
}

function DownloadCniBinaries()
{
    Write-Host "Downloading CNI binaries"
    DownloadFlannelBinaries
    md $BaseDir\cni\config -ErrorAction Ignore
    md C:\etc\kube-flannel -ErrorAction Ignore

    DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/l2bridge.exe" -Destination $BaseDir\cni\l2bridge.exe
    DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/flannel.exe" -Destination $BaseDir\cni\flannel.exe
    DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe" -Destination $BaseDir\cni\host-local.exe
    DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/net-conf.json" -Destination $BaseDir\net-conf.json
    cp $BaseDir\net-conf.json C:\etc\kube-flannel\net-conf.json
}

function DownloadWindowsKubernetesScripts()
{
    Write-Host "Downloading Windows Kubernetes scripts"
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 -Destination $BaseDir\hns.psm1
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/InstallImages.ps1 -Destination $BaseDir\InstallImages.ps1
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile -Destination $BaseDir\Dockerfile
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/stop.ps1 -Destination $BaseDir\stop.ps1
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/start-kubelet.ps1 -Destination $BaseDir\start-Kubelet.ps1 
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/start-kubeproxy.ps1 -Destination $BaseDir\start-Kubeproxy.ps1
}

function DownloadAllFiles()
{
    DownloadCniBinaries
    DownloadWindowsKubernetesScripts
}

$BaseDir = "c:\k"
md $BaseDir -ErrorAction Ignore
$helper = "c:\k\helper.psm1"
if (!(Test-Path $helper))
{
    Start-BitsTransfer https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.psm1 -Destination c:\k\helper.psm1
}
ipmo $helper

# Download All the files
DownloadAllFiles

# Prepare POD infra Images
start powershell $BaseDir\InstallImages.ps1

# Prepare Network & Start Infra services
$NetworkMode = "L2Bridge"
$NetworkName = "cbr0"

CleanupOldNetwork $NetworkName

powershell $BaseDir\start-kubelet.ps1 -RegisterOnly

ipmo C:\k\hns.psm1

# Create a L2Bridge to trigger a vSwitch creation. Do this only once
if(!(Get-HnsNetwork | ? Name -EQ "External"))
{
    New-HNSNetwork -Type $NetworkMode -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -Verbose
}

StartFlanneld -ipaddress $ManagementIP -NetworkName $NetworkName

Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $ClusterCIDR -KubeDnsServiceIP $KubeDnsServiceIP -serviceCIDR $ServiceCIDR -IsolationType $IsolationType -NetworkName $NetworkName"
Start-Sleep 10
start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName"