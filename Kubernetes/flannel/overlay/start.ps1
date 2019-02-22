Param(
    [parameter(Mandatory = $false)] $clusterCIDR="192.168.0.0/16",
    [parameter(Mandatory = $true)] $ManagementIP
)

function DownloadFlannelBinaries()
{
    md c:\flannel -ErrorAction Ignore
    DownloadFile -Url "https://github.com/coreos/flannel/releases/download/v0.11.0/flanneld.exe" -Destination c:\flannel\flanneld.exe
}

function DownloadCniBinaries()
{
    Write-Host "Downloading CNI binaries"
    DownloadFlannelBinaries
    md $BaseDir\cni\config -ErrorAction Ignore
    md C:\etc\kube-flannel -ErrorAction Ignore

    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/cni/config/cni.conf" -Destination $BaseDir\cni\config\cni.conf 
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/cni/win-overlay.exe" -Destination $BaseDir\cni\win-overlay.exe
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/flannel.exe" -Destination $BaseDir\cni\flannel.exe
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe" -Destination $BaseDir\cni\host-local.exe
    if (!(Test-Path C:\etc\kube-flannel\net-conf.json))
    {
        DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/net-conf.json" -Destination $BaseDir\net-conf.json
        cp $BaseDir\net-conf.json C:\etc\kube-flannel\net-conf.json
    }
}

function DownloadWindowsKubernetesScripts()
{
    Write-Host "Downloading Windows Kubernetes scripts"
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 -Destination $BaseDir\hns.psm1
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/InstallImages.ps1 -Destination $BaseDir\InstallImages.ps1
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile -Destination $BaseDir\Dockerfile
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/stop.ps1 -Destination $BaseDir\Stop.ps1
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/start-kubelet.ps1 -Destination $BaseDir\start-Kubelet.ps1
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/start-kubeproxy.ps1 -Destination $BaseDir\start-Kubeproxy.ps1
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
$NetworkMode = "Overlay"
$NetworkName = "vxlan0"

CleanupOldNetwork $NetworkName

powershell $BaseDir\start-kubelet.ps1 -RegisterOnly

# Open firewall for Overlay traffic
New-NetFirewallRule -Name OverlayTraffic4789UDP -Description "Overlay network traffic UDP" -Action Allow -LocalPort 4789 -Enabled True -DisplayName "Overlay Traffic 4789 UDP" -Protocol UDP -ErrorAction SilentlyContinue

ipmo C:\k\hns.psm1

# Create a L2Bridge to trigger a vSwitch creation. Do this only once
if(!(Get-HnsNetwork | ? Name -EQ "External"))
{
    New-HNSNetwork -Type $NetworkMode -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -SubnetPolicies @(@{Type = "VSID"; VSID = 9999; })  -Verbose
    Start-Sleep 10
}

# Start Flannel only after this node is registered
StartFlanneld -ipaddress $ManagementIP -NetworkName $NetworkName

GetSourceVip -ipAddress $ManagementIP -NetworkName $NetworkName
Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $clusterCIDR -NetworkName $NetworkName"

start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName -ManagementIP $ManagementIP"
