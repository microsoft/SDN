Param(
    [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] [parameter(Mandatory = $true)] $NetworkMode,
    [parameter(Mandatory = $false)] $LogDir = "C:\k"
)

function SetupDirectories($LogDir)
{
    Write-Host "Creating Kubernetes directories"
    md $BaseDir -ErrorAction Ignore
    md $LogDir -ErrorAction Ignore
    md c:\flannel -ErrorAction Ignore
    md $BaseDir\cni\config -ErrorAction Ignore
    md C:\etc\kube-flannel -ErrorAction Ignore
}

function CopyFiles()
{
    Write-Host "Copying Flannel setup files"
    cp $BaseDir\flanneld.exe c:\flannel\flanneld.exe
    cp $BaseDir\net-conf.json C:\etc\kube-flannel\net-conf.json
}

function DownloadFlannelBinaries()
{
    Write-Host "Downloading Flannel binaries"
    DownloadFile -Url  "https://github.com/coreos/flannel/releases/download/v0.11.0/flanneld.exe" -Destination $BaseDir\flanneld.exe 
}

function DownloadCniBinaries($NetworkMode)
{
    Write-Host "Downloading CNI binaries"
    DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/$NetworkMode/net-conf.json" -Destination $BaseDir\net-conf.json
    DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/$NetworkMode/cni/config/cni.conf" -Destination $BaseDir\cni\config\cni.conf
    DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/flannel.exe" -Destination $BaseDir\cni\flannel.exe
    DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe" -Destination $BaseDir\cni\host-local.exe

    if ($NetworkMode -eq "l2bridge")
    {
        DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/win-bridge.exe" -Destination $BaseDir\cni\win-bridge.exe
    }
    elseif ($NetworkMode -eq "overlay"){
        DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/overlay/cni/win-overlay.exe" -Destination $BaseDir\cni\win-overlay.exe
    }
}

function DownloadWindowsKubernetesScripts
{
    Write-Host "Downloading Windows Kubernetes scripts"
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 -Destination $BaseDir\hns.psm1
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/InstallImages.ps1 -Destination $BaseDir\InstallImages.ps1
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile -Destination $BaseDir\Dockerfile
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/stop.ps1 -Destination $BaseDir\stop.ps1
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/start-kubelet.ps1 -Destination $BaseDir\start-Kubelet.ps1
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/start-kubeproxy.ps1 -Destination $BaseDir\start-Kubeproxy.ps1
}

function DownloadAllFiles($NetworkMode)
{
    DownloadWindowsKubernetesScripts
    DownloadFlannelBinaries
    DownloadCniBinaries($NetworkMode)
}

# Setup directories
$BaseDir = "c:\k"
$NetworkMode = $NetworkMode.ToLower()
$helper = "c:\k\helper.psm1"

if (!(Test-Path $helper))
{
    Start-BitsTransfer https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.psm1 -Destination c:\k\helper.psm1
}
ipmo $helper

SetupDirectories($LogDir)

# Download files into Kubernetes base directory
DownloadAllFiles($NetworkMode)

# Copy files into runtime directories
CopyFiles

# Prepare POD infra Images
start powershell $BaseDir\InstallImages.ps1