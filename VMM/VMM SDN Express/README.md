# VMM Express - PowerShell script deployment

This script deploys SDN stack using VMM through a single configuration file. 

You will find following contents in the folder:

|- Filename -|-	Description -|
|---|---|
|VMMExpress.ps1            | This is the script file that deploys the SDN stack. Once you download it from Git, you are free to make your own customizations based on your requirement. |
|Fabricconfig.psd1         | This file accepts all the inputs for setting up SDN  |
|Fabricconfig_Example.psd1 | This is a sample file that contains dummy parameters. You can also replace the existing parameters with your own parameters. |

Apart from reducing points of human errors caused by multiple input wizards, this script also saves significant time for the fabric admins as they can specify all the parameters in one go and come back later to have complete SDN stack (including Network Controller, Software Load Balancer, and Gateway) deployed through VMM. Once you deploy SDN using this script, the complete stack is manageable by VMM UI just as it would be in case you had deployed SDN using VMM UI wizards! 

So use this script if you want to leverage best of both worlds – SDN Express like agility for deployment and rich management capability using VMM UI afterwards.

This script deploys all the Logical Networks and artefacts as described in VMM SDN deployment guide. You also have the option to re-purpose existing Management Logical Network and Logical Switch if you already have those configured. 

If script suffers a failure due to wrong input or infra issues, all the changed settings are rolled back and you can start a fresh deployment all over again.

The switch is deployed in SET mode by default. The script finds first pNIC in Trunk mode on the host and deploys Logical Switch in the SET mode on the host.In case the script can’t find such a pNIC on any host, the switch is not deployed on this host and will not get star rating during placement. The switch is deployed on one NIC and more NICs can be teamed post deployment.

In order to deploy highly available insfrastructure VMs on clustered node, Pass $true to parameter "HighlyAvailableVMs" in FabricConfig file

The cleanup in UndoNCDeployment happens only prior to NC deployment and onboarding in case of failure. Post NC onboarding success, UndoNCDeployment does not do anything as of now. Any failures further should be cleaned up before reinitiating the script.
