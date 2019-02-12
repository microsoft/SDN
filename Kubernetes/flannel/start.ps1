Param(
    [ValidateSet("l2bridge", "overlay",IgnoreCase = $true)] [parameter(Mandatory = $true)] $NetworkMode,
    [parameter(Mandatory = $false)] $ClusterCIDR="10.244.0.0/16",
    [parameter(Mandatory = $false)] $KubeDnsServiceIP="10.96.0.10",
    [parameter(Mandatory = $false)] $ServiceCIDR="10.96.0.0/12",
    [parameter(Mandatory = $false)] $InterfaceName="Ethernet",
    [parameter(Mandatory = $false)] $LogDir = "C:\k",
    [parameter(Mandatory = $true)] $ManagementIP
)

$BaseDir = "c:\k"
$NetworkMode = $NetworkMode.ToLower()
$NetworkName = "cbr0"

if ($NetworkMode -eq "overlay")
{
    $NetworkName = "vxlan0"
}

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
powershell $BaseDir\start-kubelet.ps1 -RegisterOnly -NetworkMode $NetworkMode
ipmo C:\k\hns.psm1

if ($NetworkMode -eq "l2bridge")
{
    if(!(Get-HnsNetwork | ? Name -EQ "External"))
    {
        # Create a L2Bridge network to trigger a vSwitch creation. Do this only once as it causes network blip
        New-HNSNetwork -Type $NetworkMode -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -Verbose
        Start-Sleep 10
    }
    # Start Flanneld
    StartFlanneld -ipaddress $ManagementIP -NetworkName $NetworkName
}
elseif ($NetworkMode -eq "overlay"){
    # Open firewall for Overlay traffic
    New-NetFirewallRule -Name OverlayTraffic4789UDP -Description "Overlay network traffic UDP" -Action Allow -LocalPort 4789 -Enabled True -DisplayName "Overlay Traffic 4789 UDP" -Protocol UDP -ErrorAction SilentlyContinue
    # Create a Overlay network to trigger a vSwitch creation. Do this only once
    if(!(Get-HnsNetwork | ? Name -EQ "External"))
    {
        New-HNSNetwork -Type $NetworkMode -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -SubnetPolicies @(@{Type = "VSID"; VSID = 9999; })  -Verbose
        Start-Sleep 10
    }
    # Start Flanneld
    StartFlanneld -ipaddress $ManagementIP -NetworkName $NetworkName
    Start-Sleep 1
    GetSourceVip -ipAddress $ManagementIP -NetworkName $NetworkName
}




# Start kubelet
Start powershell -ArgumentList "-File $BaseDir\start-kubelet.ps1 -NetworkMode $NetworkMode -clusterCIDR $ClusterCIDR -KubeDnsServiceIP $KubeDnsServiceIP -serviceCIDR $ServiceCIDR -InterfaceName $InterfaceName -LogDir $LogDir -NetworkName $NetworkName"
Start-Sleep 10

# Start kube-proxy
start powershell -ArgumentList " -File $BaseDir\start-kubeproxy.ps1 -NetworkMode $NetworkMode -clusterCIDR $ClusterCIDR -NetworkName $NetworkName -LogDir $LogDir"