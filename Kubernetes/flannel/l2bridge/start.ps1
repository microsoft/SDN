Param(
    [parameter(Mandatory = $false)] $ClusterCIDR="10.244.0.0/16",
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $ServiceCIDR="10.96.0.0/12",
    [parameter(Mandatory = $false)] $InterfaceName="Ethernet",
    [parameter(Mandatory = $false)] $LogDir = "C:\k",
    [parameter(Mandatory = $true)] $ManagementIP
)

$BaseDir = "c:\k"
$NetworkMode = "L2Bridge"
$NetworkName = "cbr0"

# Use helpers to setup binaries, conf files etc.
$helper = "c:\k\helper.psm1"
if (!(Test-Path $helper))
{
    Start-BitsTransfer https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.psm1 -Destination c:\k\helper.psm1
}
ipmo $helper

$install = "c:\k\install.ps1"
if (!(Test-Path $install))
{
    Start-BitsTransfer https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/install.ps1 -Destination c:\k\install.ps1
}

powershell $install -NetworkMode $NetworkMode -LogDir $LogDir


# Prepare Network & Start Infra services
CleanupOldNetwork $NetworkName
powershell $BaseDir\start-kubelet.ps1 -RegisterOnly
ipmo C:\k\hns.psm1

# Create a L2Bridge to trigger a vSwitch creation. Do this only once as it causes network blip
if(!(Get-HnsNetwork | ? Name -EQ "External"))
{
    New-HNSNetwork -Type $NetworkMode -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -Verbose
    Start-Sleep 10
}

# Start Flanneld
StartFlanneld -ipaddress $ManagementIP -NetworkName $NetworkName

# Start kubelet
Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -clusterCIDR $ClusterCIDR -KubeDnsServiceIP $KubeDnsServiceIP -serviceCIDR $ServiceCIDR -InterfaceName $InterfaceName -LogDir $LogDir -NetworkName $NetworkName"
Start-Sleep 10

# Start kube-proxy
start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName -LogDir $LogDir"