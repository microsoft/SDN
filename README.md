# Welcome to Microsoft SDN GitHub Repo
This repo includes scripts, templates, and sample switch configurations to aid admins in deploying the Software Defined Networking (SDN) Stack on Azure Stack HCI OS; Windows Server 2019; Windows Server 2016 and connecting it to their existing network topologies. It also includes sample diagnostics and examples for attaching Windows Container endpoints to a virtual network in additon to other tenant workflows. 

More details can be found on the [SDN TechNet Topic](https://docs.microsoft.com/en-us/azure-stack/hci/concepts/software-defined-networking) 

The first step in any SDN Deployment involves planning and working with a network administrator to ensure the correct IP subnets and VLANs are used as well as switch port configuration settings (e.g. VLANs to trunk, possibly DCB settings) which connect the Hyper-V Hosts (physical servers) to the physical network.   To plan and deploy Microsoft SDN, refer to the following topics on Microsoft TechNet:
* [Plan a Software Defined Network Infrastructure](https://docs.microsoft.com/en-us/azure-stack/hci/concepts/plan-software-defined-networking-infrastructure)
* [Deploy a Software Defined Network Infrastructure](https://docs.microsoft.com/en-us/azure-stack/hci/manage/sdn-express)

## SDN Fabric Deployment Options  
The SDN Stack consists of several new services and roles, not least of which is the Network Controller. The first step in the deployment is choosing the method by which you will install and configure the Network Controller. This can be done in a number of ways:
 * System Center Virtual Machine Manager (SCVMM) 'VMMExpress' PowerShell scripts 
 * **(recommended)** 'SDNExpress' PowerShell module and script.
 * SCVMM Console (GUI) Configuration and Service Template Deployment

### SDNExpress 

> **IMPORTANT:** SDN Express has undergone many simplifications and improvements in the latest release that will make it more reliable and easier to use!  If you have used SDN Express before, be sure to update your config files to use the new format.  If you are new to SDN express, then just download this repository to a local folder on one of your SDN hosts (Windows Server 2016/2019 or Azure Stack HCI) and run ./SDNExpress.ps1 for an interactive UI to help define your configuration and deploy!  

The SDNExpress scripts will deploy the entire SDN Fabric including Network Controller, Software Load Balancer, and Gateway. The script will use a configuration file as input which defines the IP subnet prefixes, VLANs, credentials, Hyper-V Host servers, and BGP Peering info required by the SDN Fabric.  At a minimum, a user will need to download the SDNExpress scripts to a host from which deployment will occur. The MultiNodeSampleConfig.psd1 configuration file can be copied and customized for your environment or you can just run the SDNExpress.ps1 script for a guided interface for deployment or saving to a config file. After the fabric resources are setup, refer to the [SDN topics on docs.microsoft.com](https://docs.microsoft.com/en-us/azure-stack/hci/concepts/software-defined-networking) for usage of the network controller PowerShell cmdlets, or if this is part of a Hyper-converged deployment try out the preview of the [Windows Admin Center](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewserver) for management of your SDN deployment. 

You can optionally use SDNExpressModule.psm1 as a powershell module in your own scripts for doing more advanced deployments and for scaling out to add additional host, mux or gateway capacity.

### VMMExpress
The VMMExpress scripts will deploy the entire SDN Fabric (similar to SDNExpress) using SCVMM PowerShell. This deployment option requires that you have SCVMM installed in your environment and have added the Hyper-V hosts as managed servers through the VMM Console. Once you deploy SDN using this script, the complete stack is manageable by VMM UI just as it would be in case you had deployed SDN using VMM UI wizards! So use this script if you want to leverage best of both worlds – SDN Express like agility for deployment and rich management capability using VMM UI afterwards. 

This script deploys all the Logical Networks and artefacts as described in VMM SDN deployment guide. You also have the option to re-purpose existing Management Logical Network and Logical Switch if you already have those configured. If script suffers a failure due to wrong input or infra issues, all the changed settings are rolled back and you can start a fresh deployment all over again.

> Note: SET enabled switch deployment is currently not supported in this script. The script finds first pNIC in Trunk mode on the host and deploys Logical Switch in the standalone mode on the host. In case the script can’t find such a pNIC on any host, the switch deployment will fail. If you need SET enabled deployment, you need to deploy the SET enabled switch out of band and then specify the name of the switch in the script at the time of deployment.

### SCVMM Console Configuration with Service Template Deployment 

Please reference the [Setup a Software Defined Network infrastructure in the VMM fabric](https://docs.microsoft.com/en-us/system-center/vmm/deploy-sdn?view=sc-vmm-2019) TechNet topic to:
 * [Setup the Network Controller](https://docs.microsoft.com/en-us/system-center/vmm/sdn-controller?view=sc-vmm-2019)
 * [Setup the Software Load Balancer](https://docs.microsoft.com/en-us/system-center/vmm/sdn-slb?view=sc-vmm-2019)
 * [Setup the SDN (RRAS) Gateway](https://docs.microsoft.com/en-us/system-center/vmm/sdn-gateway?view=sc-vmm-2019)

## SDN Fabric Services and roles

### Network Controller 
The Network Controller role exposes a RESTful API through which management systems (e.g. SCVMM, PowerShell, etc.) can create network resources and policy using a published API and JSON schema. This API can be invoked through Network Controller PowerShell modules or the SCVMM Console. 
> Note: The Azure Stack HCI and the Windows Server 2016/2019  SDN Platform has more capabilities than those exposed through System Center Virtual Machine Manager (SCVMM)

It can also be called directly using the Invoke-WebRequest PowerShell module (or curl) and appropriate HTTP GET, POST, DELETE methods with JSON Body and/or Returned output.   

After the Network Controller is deployed, additional SDN fabric services and infrastructure VM(s) - Software Load Balancer Multiplexers, RRAS (SDN) Gateways - can be created and attached to the Network Controller. After each service and infrastructure VM is deployed, new tenant scenarios will become available.  
> Note: It is important to note that simple tenant operations such as creating an Overlay Virtual Network and attaching VMs to can be done immediately after the Network Controller is installed without any other services (e.g. SLB or Gateway) deployed. 

Tenant Scenarios available after Network Controller deployed:
 1. Create Overlay Virtual Network 
 2. Create virtual subnets
 3. Create VM NICs to attach VMs to a virtual subnet 
 4. Create Network Security Groups Access Control Lists (ACLs) and apply these to virtual subnets or VM NICs
 5. Create QoS policy for setting bandwitch caps or inbound port reservations and apply these to VM NICs

### Software Load Balancer
The Software Load Balancer (SLB) Multiplexer (Mux) role provides a Stateless Layer-3/4 Load Balancer that can be scaled-out to multiple instances. An SLB Host Agent is deployed on each Hyper-V Host which is running a load-balanced VM (Dynamic IP - DIP) to support Direct Server Return / Mux By-pass, Internal Load Balancing optimizations through ICMP Redirects and can perform Source NAT for VMs requring external network (e.g. internet) access. 

The Network Controller must be installed first before using the SLB Mux. SLB configuration is handled through the Network Controller's RESTful API. 

Tenant Scenarios available after Software Load Balancer deployed:
 1. Ingress Load-Balancing through a Virtual IP (VIP) to a set of back-end Dynamic IP (DIP) VMs
 2. East-West Load-Balancing through a VIP
 3. Outbound NAT (Source NAT) for external network connectivity
 4. Inbound NAT (Destination NAT) for direct access to VMs and services     

### SDN (RRAS) Gateway
The SDN Gateways use the Routing and Remote Access Services (RRAS) role to provide multiple tunnels, connections, and routes to remote sites or physical networks. The gateways support a highly-available M:N redundancy model as well as multi-tenancy.

Tenant Scenarios available after RRAS (SDN) Gateway deployed:
 1. Create IPSec tunnels with IKEv2 key exchange between two sites
 2. Create GRE tunnels between two sites or an MPLS Edge Router
 3. Create a Forwarding Gateway to route between virtual networks and physical networks
 4. Provide transit routing  

## Contributing

Pull Requests are always welcome. To get started, take a look at CONTRIBUTING.md 


This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
