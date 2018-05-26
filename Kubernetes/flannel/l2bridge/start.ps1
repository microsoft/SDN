Param(
    [parameter(Mandatory = $true)] $ClusterCIDR,
    [parameter(Mandatory = $true)] $ManagementIP,
    [parameter(Mandatory = $true)] $KubeDnsServiceIP,
    [parameter(Mandatory = $true)] $ServiceCIDR
)

function DownloadFlannelBinaries()
{
    md c:\flannel -ErrorAction Ignore
    Start-BitsTransfer  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/flanneld.exe" -Destination c:\flannel\flanneld.exe
}

function DownloadCniBinaries()
{
    Write-Host "Downloading CNI binaries"
    DownloadFlannelBinaries
    md $BaseDir\cni\config -ErrorAction Ignore
    md C:\etc\kube-flannel -ErrorAction Ignore

    Start-BitsTransfer  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/l2bridge.exe" -Destination $BaseDir\cni\l2bridge.exe
    Start-BitsTransfer  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/flannel.exe" -Destination $BaseDir\cni\flannel.exe
    Start-BitsTransfer  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe" -Destination $BaseDir\cni\host-local.exe
    cp $BaseDir\net-conf.json C:\etc\kube-flannel\net-conf.json
}

function DownloadWindowsKubernetesScripts()
{
    Write-Host "Downloading Windows Kubernetes scripts"
    Start-BitsTransfer  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 -Destination $BaseDir\hns.psm1
    Start-BitsTransfer  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/InstallImages.ps1 -Destination $BaseDir\InstallImages.ps1
    Start-BitsTransfer  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile -Destination $BaseDir\Dockerfile
    Start-BitsTransfer  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/stop.ps1 -Destination $BaseDir\stop.ps1
}

function DownloadAllFiles()
{
    DownloadCniBinaries
    DownloadWindowsKubernetesScripts
}

function StartFlanneld($ipaddress)
{
    CleanupOldNetwork

    # Start FlannelD, which would recreate the network.
    # Expect disruption in node connectivity for few seconds
    pushd 
    cd C:\flannel\
    [Environment]::SetEnvironmentVariable("NODE_NAME", (hostname).ToLower())
    start C:\flannel\flanneld.exe -ArgumentList "--kubeconfig-file=C:\k\config --iface=$ipaddress --ip-masq=1 --kube-subnet-mgr=1" -NoNewWindow
    popd

    # Wait till the network is available
    while( !(Get-HnsNetwork -Verbose | ? Type -EQ $NetworkMode.ToLower()) )
    {
        Write-Host "Waiting for the Network to be created"
        Start-Sleep 10
    }
}

function CleanupOldNetwork()
{
    $hnsNetwork = Get-HnsNetwork | ? Type -EQ $NetworkMode.ToLower()

    if ($hnsNetwork)
    {
        # Cleanup all containers
        docker ps -q | foreach {docker rm $_ -f} 

        Write-Host "Cleaning up old HNS network found" 
        Remove-HnsNetwork $hnsNetwork
    }
    Start-Sleep 10
}

$BaseDir = "c:\k"
md $BaseDir -ErrorAction Ignore
# Download All the files
DownloadAllFiles

# Prepare POD infra Images
start powershell $BaseDir\InstallImages.ps1

# Prepare Network & Start Infra services
$NetworkMode = "L2Bridge"
$NetworkName = "cbr0"

powershell $BaseDir\start-kubelet.ps1 -RegisterOnly


StartFlanneld $ManagementIP

Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $ClusterCIDR -KubeDnsServiceIP $KubeDnsServiceIP -serviceCIDR $ServiceCIDR -NetworkName $NetworkName"
Start-Sleep 10
start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName"
