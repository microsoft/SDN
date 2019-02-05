Param(
    [parameter(Mandatory = $false)] $ClusterCIDR="10.244.0.0/16",
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $ServiceCIDR="10.96.0.0/12",
    [parameter(Mandatory = $false)] $InterfaceName="Ethernet",
    [parameter(Mandatory = $false)] $LogDir = "C:\k",
    [parameter(Mandatory = $true)] $ManagementIP
)

$BaseDir = "c:\k"
$NetworkMode = "Overlay"
$NetworkName = "vxlan0"


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

# Open firewall for Overlay traffic
New-NetFirewallRule -Name OverlayTraffic4789UDP -Description "Overlay network traffic UDP" -Action Allow -LocalPort 4789 -Enabled True -DisplayName "Overlay Traffic 4789 UDP" -Protocol UDP -ErrorAction SilentlyContinue

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
Start-Sleep 10

start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkName $NetworkName -ManagementIP $ManagementIP"