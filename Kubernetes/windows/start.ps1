Param(
    [parameter(Mandatory = $true)] [string] $masterIp,
    [parameter(Mandatory = $false)] $clusterCIDR="192.168.0.0/16"
)

$BaseDir = "c:\k"

ipmo $BaseDir\helper.psm1

$BaseDir = "c:\k"
md $BaseDir -ErrorAction Ignore

# Download All the files
# DownloadAllFiles

# Prepare POD infra Images
start powershell $BaseDir\InstallImages.ps1

# Prepare Network & Start Infra services
$NetworkMode = "L2Bridge"

# WinCni needs the networkType and network name to be the same
$NetworkName = "l2bridge"

CleanupOldNetwork $NetworkMode

Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $clusterCIDR -NetworkName $NetworkName"

WaitForNetwork $NetworkMode

start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName"

powershell -File $BaseDir\AddRoutes.ps1 -masterIp $masterIp