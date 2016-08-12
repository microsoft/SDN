This guide will be published on TechNet shortly. Until then, these are the instructions to follow when attaching a container endpoint to an overaly virtual network created through with the Microsoft SDN Stack.


## Pre-requistes
 * An SDN infrastructure with the Network Controller has been deployed
 * A tenant virtual network has been created
 * A tenant Virtual Machine has been deployed with the Windows Container feature enabled and Docker installed

## Workflow

1. [Hyper-V Host] Add multiple IP configurations to an existing VM NIC resource through Network Controller
2. [Hyper-V Host] Enable the network proxy on the host to allocate CA IP Addresses for container endpoints [ConfigureMCNP.ps1](location>)
3. [Container Host VM] Install the private cloud plug-in to assign CA IP addresses to container endpoints [InstallPrivateCloudPlugin.ps1](location)
4. [Container Host VM] Create an *l2bridge* or *l2tunnel* network using docker
 
> Multiple IP configurations is not supported on VM NIC resources created through System Center Virtual Machine Manager. It is recommended for these types of deployments that you create the VM NIC resource out of band using Network Controller PowerShell

### Add Multiple IP Configurations

For this example, we will assume that the VM NIC of the Tenant VM already has one IP configuration with IP address of 192.168.1.9 and is attached to a VNet Resource ID of 'VNet1' and VM Subnet Resource of 'Subnet1' in the 192.168.1.0/24 IP subnet. We will add 10 IPs for containers from 192.168.1.101 - 192.168.1.110.

```powershell
Import-Module NetworkController

# Specify Network Controller REST IP or FQDN
$uri = "<NC REST IP or FQDN>"
$vnetResourceId = "VNet1"
$vsubnetResourceId = "Subnet1"

$vmnic= Get-NetworkControllerNetworkInterface -ConnectionUri $uri | where {$_.properties.IpConfigurations.Properties.PrivateIPAddress -eq "192.168.1.9" }
$vmsubnet = Get-NetworkControllerVirtualSubnet -VirtualNetworkId $vnetResourceId -ResourceId $vsubnetResourceId -ConnectionUri $uri

# For this demo, we will assume an ACL has already been defined; any ACL can be applied here
$allowallacl = Get-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId "AllowAll"


foreach ($i in 1..10)
{
    $newipconfig = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
    $props = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties

    $resourceid = "IP_192_168_1_1"
    if ($i -eq 10) 
    {
        $resourceid += "10"
        $ipstr = "192.168.1.110"
    }
    else
    {
        $resourceid += "0$i"
        $ipstr = "192.168.1.10$i"
    }
    
    $newipconfig.ResourceId = $resourceid
    $props.PrivateIPAddress = $ipstr    
    
    $props.PrivateIPAllocationMethod = "Static"
    $props.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
    $props.Subnet.ResourceRef = $vmsubnet.ResourceRef
    $props.AccessControlList = new-object Microsoft.Windows.NetworkController.AccessControlList
    $props.AccessControlList.ResourceRef = $allowallacl.ResourceRef

    $newipconfig.Properties = $props
    $vmnic.Properties.IpConfigurations += $newipconfig
}

New-NetworkControllerNetworkInterface -ResourceId $vmnic.ResourceId -Properties $vmnic.Properties -ConnectionUri $uri
```

### Enable the Network Proxy

Run this script on the **Hyper-V Host** which is hosting the container host (tenant) VM to enable the network proxy to allocate multiple IP addresses for the container host VM

```powershell
PS C:\> ConfigureMCNP.ps1
```

### Install Private Cloud plug-in

Run this script inside the **container host (tenant) VM** to allow the Host Networking Service (HNS) to communicate with the network proxy on the Hyper-V Host

```powershell
PS C:\> InstallPrivateCloudPlugin.ps1
```

### Create an l2bridge Container Network

On the **container host (tenant) VM** use _docker network create_ command to create an l2bridge network

```powershell
# Create the container network
C:\> docker network create -d l2bridge --subnet="192.168.1.0/24" --gateway="192.168.1.1" MyContainerOverlayNetwork

# Attach a container to the MyContainerOverlayNetwork 
C:\> docker run -it --network=MyContainerOverlayNetwork <image> <cmd>
```

> Static IP assignment is not supported with **l2bridge** or **l2tunnel* container networks when used with the Microsoft SDN Stack




