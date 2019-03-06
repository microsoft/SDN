Param(
    [parameter(Mandatory = $true)] [string] $masterIp,
    [parameter(Mandatory = $false)] $clusterCIDR="192.168.0.0/16"
)

$GithubSDNRepository = 'Microsoft/SDN'
if ((Test-Path env:GITHUB_SDN_REPOSITORY) -and ($env:GITHUB_SDN_REPOSITORY -ne ''))
{
    $GithubSDNRepository = $env:GITHUB_SDN_REPOSITORY
}

function DownloadCniBinaries()
{
    Write-Host "Downloading CNI binaries"
    md $BaseDir\cni\config -ErrorAction Ignore

    DownloadFile -Url "https://github.com/$GithubSDNRepository/raw/master/Kubernetes/windows/cni/wincni.exe" -Destination $BaseDir\cni\wincni.exe
}

function DownloadWindowsKubernetesScripts()
{
    Write-Host "Downloading Windows Kubernetes scripts"
    DownloadFile -Url "https://github.com/$GithubSDNRepository/raw/master/Kubernetes/windows/hns.psm1" -Destination $BaseDir\hns.psm1
    DownloadFile -Url "https://github.com/$GithubSDNRepository/raw/master/Kubernetes/windows/InstallImages.ps1" -Destination $BaseDir\InstallImages.ps1
    DownloadFile -Url "https://github.com/$GithubSDNRepository/raw/master/Kubernetes/windows/Dockerfile" -Destination $BaseDir\Dockerfile
    DownloadFile -Url "https://github.com/$GithubSDNRepository/raw/master/Kubernetes/windows/stop.ps1" -Destination $BaseDir\stop.ps1
    DownloadFile -Url "https://github.com/$GithubSDNRepository/raw/master/Kubernetes/windows/start-kubelet.ps1" -Destination $BaseDir\start-kubelet.ps1
    DownloadFile -Url "https://github.com/$GithubSDNRepository/raw/master/Kubernetes/windows/start-kubeproxy.ps1" -Destination $BaseDir\start-Kubeproxy.ps1
    DownloadFile -Url "https://github.com/$GithubSDNRepository/raw/master/Kubernetes/windows/AddRoutes.ps1" -Destination $BaseDir\AddRoutes.ps1
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
    Start-BitsTransfer "https://raw.githubusercontent.com/$GithubSDNRepository/master/Kubernetes/windows/helper.psm1" -Destination c:\k\helper.psm1
}
ipmo $helper

DownloadAllFiles

# Prepare POD infra Images
start powershell $BaseDir\InstallImages.ps1

# Prepare Network & Start Infra services
$NetworkMode = "L2Bridge"

# WinCni needs the networkType and network name to be the same
$NetworkName = "l2bridge"

CleanupOldNetwork $NetworkName

Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $clusterCIDR -NetworkName $NetworkName"

WaitForNetwork $NetworkName

start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName"

powershell -File $BaseDir\AddRoutes.ps1 -masterIp $masterIp