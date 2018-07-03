Param(
    [parameter(Mandatory = $false)] $clusterCIDR="192.168.0.0/16",
    [parameter(Mandatory = $true)] $ManagementIP
)

ipmo c:\k\helper.psm1

function DownloadFlannelBinaries()
{
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/flanneld.exe" -Destination c:\flannel\flanneld.exe
}

function DownloadCniBinaries()
{
    Write-Host "Downloading CNI binaries"
    DownloadFlannelBinaries
    md $BaseDir\cni -ErrorAction Ignore
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/cni/config/cni.conf" -Destination $BaseDir\cni\config\cni.conf 
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/cni-conf.json" -Destination c:\etc\kube-flannel\net-conf.json
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/overlay.exe" -Destination $BaseDir\cni\overlay.exe
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/flannel.exe" -Destination $BaseDir\cni\flannel.exe
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/host-local.exe" -Destination $BaseDir\cni\host-local.exe
}

function DownloadWindowsKubernetesScripts()
{
    Write-Host "Downloading Windows Kubernetes scripts"
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 -Destination $BaseDir\hns.psm1
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/InstallImages.ps1 -Destination $BaseDir\InstallImages.ps1
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile -Destination $BaseDir\Dockerfile
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Stop.ps1 -Destination $BaseDir\Stop.ps1
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/start-kubelet.ps1 -Destination $BaseDir\start-Kubelet.ps1
    DownloadFile -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/start-kubeproxy.ps1 -Destination $BaseDir\start-Kubeproxy.ps1
}

function DownloadAllFiles()
{
    DownloadCniBinaries
    DownloadWindowsKubernetesScripts
}

function StartFlanneld($ipaddress)
{
    CleanupOldNetwork $NetworkMode

    # Start FlannelD, which would recreate the network.
    # Expect disruption in node connectivity for few seconds
    pushd 
    cd C:\flannel\
    [Environment]::SetEnvironmentVariable("NODE_NAME", (hostname).ToLower())
    start C:\flannel\flanneld.exe -ArgumentList "--kubeconfig-file=C:\k\config --iface=$ipaddress --ip-masq=1 --kube-subnet-mgr=1" # -NoNewWindow
    popd

    WaitForNetwork $NetworkMode
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

powershell $BaseDir\start-kubelet.ps1 -RegisterOnly

# Open firewall for Overlay traffic
New-NetFirewallRule -Name OverlayTraffic4789UDP -Description "Overlay network traffic UDP" -Action Allow -LocalPort 4789 -Enabled True -DisplayName "Overlay Traffic 4789 UDP" -Protocol UDP -ErrorAction SilentlyContinue

# Start Flannel only after this node is registered
StartFlanneld $ManagementIP

Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $clusterCIDR -NetworkName $NetworkName"

# Remote endpoint should be programmed by Flanneld

# Wait for sometime to start Proxy, as it would race with Flanneld VXLan agent to program the RemoteEndpoint.
#Start-Sleep 60
#start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName"
