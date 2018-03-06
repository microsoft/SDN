Param(
    [parameter(Mandatory = $true)] [string] $masterIp,
    [parameter(Mandatory = $false)] $clusterCIDR="192.168.0.0/16"
)

$BaseDir = "c:\k"

# Prepare POD infra Images
start powershell $BaseDir\InstallImages.ps1

# Prepare Network & Start Infra services
$NetworkMode = "L2Bridge"
Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $clusterCIDR -NetworkMode $NetworkMode"

Start-Sleep 10

while( !(Get-HnsNetwork -Verbose | ? Name -EQ $NetworkMode.ToLower()) )
{
    Write-Host "Waiting for the Network to be created"
    Start-Sleep 10
}

powershell -File $BaseDir\AddRoutes.ps1 -masterIp $masterIp

start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkMode $NetworkMode"

