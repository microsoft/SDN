#Frequently Asked Questions#
*This is a work in progress*

### System Requirements ###
1. What are the physical hardware requirements (e.g. CPU, memory, disk) for the Windows Server 2016 SDN Stack?
  - *Refer to TechNet for the [system requirements](https://technet.microsoft.com/en-US/library/mt605207.aspx)*
2. What are the system requirements for each server role in the Windows Server 2016 SDN Stack?
  - *Refer to TechNet for the [role requirements](https://technet.microsoft.com/en-US/library/mt605207.aspx) 
3. Can I try out SDN on a single host? I would like to build a cloud with 10 VMs and 10 tenants.
  - *Yes, a single-node POC setup is available to try for SDN and Microsoft Azure Stack (MAS) components. Link is coming soon...*

### Scenarios ###
1. What scenarios can I try with the new SDN Stack?
  - *The SDN Stack in Windows Server 2016 includes many new scenarios which can be used in both lab / POC and production environments. These scenarios include:*
    1. Create a virtual network / subnet
    2. Create a VM NIC and add it to a virtual subnet
    3. Create a front-end IP to be load balanced using the SLB MUX
    4. Create a set of back-end IPs to be

### Additional Documentation ###
*Answers to these questions are coming soon. All Create, Read, Update, and Delete (CRUD) operations for network policy will be done through the Network Controller using PowerShell wrappers for the actual REST API.*

1. How do I create a new virtual network?
2. How do I create a new virtual subnet?
3. How do I create a new Access Control List (ACL) to block TCP port 80 traffic?
4. How do I create new, front-end Virtual IP (VIP) address?
5. *Suggestions...?*

### High Availability ###
1. What happens to my network if the Network Controller fails?
2. What happens to my network if the the Software Load Balancer (SLB) Mux fails?
3. What happens to my network if one of the gateways goes down?

### Other Questions ###
*Suggestions...*


