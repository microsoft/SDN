Param(
    [parameter(Mandatory = $false)] $clusterCIDR="192.168.0.0/16",
    [parameter(Mandatory = $true)] $ManagementIP
)

function DownloadFileOverHttps()
{
    param(
    [parameter(Mandatory = $true)] $Url,
    [parameter(Mandatory = $true)] $DestinationPath
    )

    if (Test-Path $DestinationPath)
    {
        Write-Host "File $DestinationPath already exists."
        return
    }

    $secureProtocols = @()
    $insecureProtocols = @([System.Net.SecurityProtocolType]::SystemDefault, [System.Net.SecurityProtocolType]::Ssl3)

    foreach ($protocol in [System.Enum]::GetValues([System.Net.SecurityProtocolType]))
    {
        if ($insecureProtocols -notcontains $protocol)
        {
            $secureProtocols += $protocol
        }
    }
    [System.Net.ServicePointManager]::SecurityProtocol = $secureProtocols

    try {
        curl $Url -UseBasicParsing -OutFile $DestinationPath -Verbose
        Write-Log "Downloaded $Url=>$DestinationPath"
    } catch {
        Write-Error "Failed to download $Url"
    }
}

function DownloadFlannelBinaries()
{
    DownloadFileOverHttps -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/flanneld.exe" -DestinationPath c:\flannel\flanneld.exe
}

function DownloadCniBinaries()
{
    Write-Host "Downloading CNI binaries"
    DownloadFlannelBinaries
    md $BaseDir\cni -ErrorAction Ignore
    DownloadFileOverHttps -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/config/cni.conf" -DestinationPath $BaseDir\cni\config\cni.conf
    DownloadFileOverHttps -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/l2bridge.exe" -DestinationPath $BaseDir\cni\l2bridge.exe
    DownloadFileOverHttps -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/flannel.exe" -DestinationPath $BaseDir\cni\flannel.exe
    DownloadFileOverHttps -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe" -DestinationPath $BaseDir\cni\host-local.exe
    DownloadFileOverHttps -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/net-conf.json" -DestinationPath C:\etc\kube-flannel\net-conf.json
}

function DownloadWindowsKubernetesScripts()
{
    Write-Host "Downloading Windows Kubernetes scripts"
    DownloadFileOverHttps -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 -DestinationPath $BaseDir\hns.psm1
    DownloadFileOverHttps -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/InstallImages.ps1 -DestinationPath $BaseDir\InstallImages.ps1
    DownloadFileOverHttps -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile -DestinationPath $BaseDir\Dockerfile
    DownloadFileOverHttps -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/stop.ps1 -DestinationPath $BaseDir\stop.ps1
    DownloadFileOverHttps -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/start-kubelet.ps1 -DestinationPath $BaseDir\start-Kubelet.ps1
    DownloadFileOverHttps -Url https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/start-kubeproxy.ps1 -DestinationPath $BaseDir\start-Kubeproxy.ps1
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
    start C:\flannel\flanneld.exe -ArgumentList "--kubeconfig-file=C:\k\config --iface=$ipaddress --ip-masq=1 --kube-subnet-mgr=1" # -NoNewWindow
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

Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $clusterCIDR -NetworkName $NetworkName"
Start-Sleep 10
start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName"
