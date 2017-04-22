# This is the configuration file for VMM Express. All the paremeters should be
# filled in correctly for smooth deployment of VMM Express.

@{

    AllNodes = 
    @(
        @{ 
            
							
            ###########################
            #  VM Creation variables  #
            ###########################
            
            # Name of the VHD or VHDX to use for VM creation. Must Exist in the
            # VMM Library            
            VHDName=""
            
            # VMM Library share to be used for keeping the resources.
            VMMLibrary=""
            
            # Product key Can be blank if using a volume license VHD or VHDX, or you are
            #deploying in eval mode.  (Don't forget to press "skip" while VM creation).
            ProductKey="" 

            #Generation of VM to be used for deployment, Values are:
            # 1. Gen1 - for Generation 1 VM
            # 2. Gen2 - for Generation 2 VM
            Generation=""

            #Type of Deployment. The values are :
            #Standalone : For single Node 
            #Production : For 3-node
            DeploymentType=""	
			
			#Higly Available VM. Do you want the infrastructural VMs to be deployed on
			#Clustered Host and being higly Available ? If yes pass $true else $false
			HighlyAvailableVMs = ""
			
			StorageClassification = ""
            
            #leave it if you want default IPvAddressType to be taken which is static
            # else change it to "Dynamic"
            IPv4AddressType=""
                        
            #Host Group to be Managed by Network Controller. All the Host to be 
            #Managed by Network controller should be part of this Host Group
            NCHostGroupName=""
            
            ######################################################################
            #  Section to be filled if the Logical switch and Logical Network    #
            #  is already deployed for NC. You should do this if SET support is  #
            #  required. If you want VMM express to deploy the                   #
            #  Logical switch and Management Network, leave it as it is.         #
            ######################################################################
            
            #Do you have an existing logical switch and the switch is deployed on all
            #the host you wish to Manage by NC. Values are $true or $false
            IsLogicalSwitchDeployed = 
            
            #if above is true give the name of logical switch			
            LogicalSwitch  = ""

            # Do you have existing Management Network that you would like to use.
            # Values are : $true or $false
            IsManagementVMNetworkExisting = $true

            #if above is true give the name of ManagementVMNetwork
            ManagementVMNetwork = "" 

            #Uplink Port Profile to be used
            UplinkPortProfile = ""            
             
            #====================================================================================
            #The below set of Parameters are required for creation of Management Logical Network
            #====================================================================================
             LogicalNetworks = @(
			    @{
                    Name = "HNVPA"                                      # Don't change this. There should be no LN with this name in VMM
                    Subnets = @(
                        @{
                            VLANID =  0                                  #Example: 11
                            AddressPrefix = ""                          #Example: "10.0.10.0/24"
                            DNS = @("")                                 #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = ""                               #Example: "10.0.10.1"
                            PoolStart = ""                              #Example: "10.0.10.50"
                            PoolEnd = ""                                #Example: "10.0.10.150"
                       }
                    )
                },
				@{
                    Name = "Transit"                                   # Don't change this. There should be no LN with this name in VMM                               
                    Subnets = @(
                        @{
                            VLANID =   0                                #Example: 12
                            AddressPrefix = ""                         #Example: "10.0.40.0/24"
                            DNS = @("")                                #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = ""                              #Example: "10.0.40.1"
                            PoolStart = ""                             #Example: "10.0.40.5"
                            PoolEnd = ""                               #Example: "10.0.40.100"
                        }  
                    )
                }, 
                @{
                    #The first IP address (PoolStart) for this logical network is 
                    #automatically assigned to the SLB Manager.Other addresses such
                    #as the GatewayPublicIPAddress will start after that.
                    Name = "PublicVIP"                                # Don't change this. There should be no LN with this name in VMM
                    Subnets = @(
                        @{
                            VLANID = 0
                            AddressPrefix = ""                        #Example: "10.0.20.0/24"
                            DNS = @("")                               #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = ""                             #Example: "10.0.20.1"
                            PoolStart = ""                            #Example: "10.0.20.5"
                            PoolEnd = ""                              #Example: "10.0.20.100"
                            IsPublic = $true
                        }  
                    )
                },
                @{
                    #The first IP address (PoolStart) for this logical network is 
                    #automatically assigned to the SLB Manager.Other addresses such
                    #as the GatewayPublicIPAddress will start after that.
                    Name = "PrivateVIP"                                # Don't change this. There should be no LN with this name in VMM
                    Subnets = @(
                        @{
                            VLANID = 0
                            AddressPrefix = ""                         #Example: "10.0.20.0/24"
                            DNS = @("")                                #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = ""                              #Example: "10.0.20.1"
                            PoolStart = ""                             #Example: "10.0.20.5"
                            PoolEnd = ""                               #Example: "10.0.20.100"
                            IsPublic = $false
                        }  
                    )
                },
                @{
                    #This is used for onboarding Gateway
                    Name = "GREVIP"                                # Don't change this. There should be no LN with this name in VMM
                    Subnets = @(
                        @{
                            VLANID = 0
                            AddressPrefix = ""                         #Example: "10.0.20.0/24"
                            DNS = @("")                                #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = ""                              #Example: "10.0.20.1"
                            PoolStart = ""                             #Example: "10.0.20.5"
                            PoolEnd = ""                               #Example: "10.0.20.100"
                            IsPublic = $false
                        }  
                    )
                },						
                @{
				    #if Management VM Network is not deployed give the ManagementVMNetwork information.
                    Name = "NC_Management"                                # Don't change this. There should be no LN with this name in VMM
                    Subnets = @(
                    @{
                        VLANID =   0                                    #Example: 7
                        AddressPrefix = ""                             #Example: "10.0.0.0/24"
                        DNS = @("")                                    #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                        Gateways = ""                                  #Example: "10.0.40.1"
                        PoolStart = ""                                 #Example: "10.0.0.5"
                        PoolEnd = ""                                   #Example: "10.0.0.100"
                        ReservedIPset =  ""                            #This IP will be used for NC Rest API                           
                    }  
                    )
                }

            )
								
            #=========================================================================================
            # The following set of paremeters are required for importing VMM service Template,
            # configuring the Service Template and Deploying the service Template. The list may change
            # during the develpoment phase
            #==========================================================================================

            # Make this true if self signed certificate is to be used
            # Example : $True , $False
            IsCertSelfSigned =  

            #The password for server certificate. This sertificate will be installed on the Host
            ServerCertificatePassword=""	            

            # The following are service settings required for configuring and
            # deploying the service template imported client security Group Name
            ClientSecurityGroupName= ""

            # Local Admin credentials
            # The local admin user name will be .\Administrator
            LocalAdminPassword= ""    

            # Management Domain Account Which will be used for NC Deployment
            ManagementDomainUser=""
            ManagementDomainUserPassword=""

             # This is the domain which NC VMs will join
            ManagementDomainFDQN=""		

            #Managemet Security Group Name
            ManagementSecurityGroupName=""

            
            
            # Prefix to be added to infrastructural VMs created. Put the prefix such
            # that it makes VM name unique as this is the machine name of VM and should be unique.
            # Keep it as 2 - 3 characters            
            ComputerNamePrefix = ""   

            # This will be registered as NC End point
            RestName = ""
            
            ##################################
            #  Deoloyment Control Switches   #
            ##################################
                                    
            # Do you want to deploy NC. Values are $true , $false
            DeployNC = $false
			
			#Do you want to create NC managed HNVPA, Transit networks. This are required if SLB and GW needs to be deployed
            createNCManagedNetworks = $false
            #Do you want to Deploy SLB. Values are $true , $false
            DeploySLB =   $false

            #Do you want to deploy GW. Values are $true , $false
            DeployGW = $false  			
        };
           
     );
}
