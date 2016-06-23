This repo includes PowerShell scripts for setting up the [Microsoft Software Defined Networking](https://technet.microsoft.com/en-us/library/mt403307.aspx) (SDN) Stack using Windows Server 2016 Technical Preview. 


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

