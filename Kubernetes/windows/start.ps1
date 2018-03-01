
$BaseDir = "c:\k"

# Prepare POD infra Images
start powershell $BaseDir\InstallImages.ps1

# Prepare Network & Start Infra services
$NetworkMode = "L2Bridge"
$hnsNetwork = Get-HnsNetwork | ? Name -EQ $NetworkMode.ToLower()
start powershell $BaseDir\start-kubelet.ps1

if (!$hnsNetwork)
{
    Start-Sleep 90
}
else 
{
    Start-Sleep 5
}

start powershell $BaseDir\AddRoutes.ps1
start powershell $BaseDir\start-kubeproxy.ps1




