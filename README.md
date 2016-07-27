At a minimum, a user will need to download the SDNExpress scripts to a host from which deployment will occur. The directory containing the SDNExpress scripts will need to have Read/Write permissions open for all hosts to be used in the deployment. The Config.psd1 configuration file will need to be customized for your environment and will be used by the SDNExpress.ps1 script to setup the SDN fabric resources. After the fabric resources are setup, the SDNExpressTenant.ps1 script can be run to create a sample, single-tenant, two-tier application (Web and Database) which uses default ACLs and two virtual subnets. 

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
=======
The SDNExpress folder contains six folders: 

* **AgentConf**

  The AgentConf folder holds fresh copies of OVSDB schemas used by the SDN Host Agent on each Windows Server 2016 Hyper-V host to program network policy.

* **TenantApps**

 The TenantApps folder contains sample configuration for a two-tier application (Web and Database) deployment.
 
* **Tools**

 The Tools folder is a place you can put any files that you want to automatically copied to your hosts and virtual machines.

* **Certs**

 This is a temporary location for certificates created during deployment.

* **Images**

 This is where you copy your operating system VHDX  files.


* **Scripts**

  The scripts folder contains PowerShell and Desired State Configuration (DSC) scripts used to configure both fabric and tenant resources in a sample SDN deployment.




Click **Clone or download** on the Microsoft SDN repository to download the SDN-master.zip file. Read and follow the planning and deployment topics referenced below to deploy Microsoft SDN in your datacenter.

To plan and deploy Microsoft SDN, refer to the following topics on Microsoft TechNet:
* [Plan a Software Defined Network Infrastructure](https://technet.microsoft.com/en-us/library/mt605207.aspx)
* [Deploy a Software Defined Network Infrastructure](https://technet.microsoft.com/en-us/library/mt590901.aspx)
