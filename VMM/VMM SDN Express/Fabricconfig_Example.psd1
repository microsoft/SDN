# This is the sample configuration file for VMM Express. All the paremeters should be
# modified according to your setup for correct deployment of VMM Express.

@{

    AllNodes = 
    @(
        @{ 
            
							
            ###########################
            #  VM Creation variables  #
            ###########################
            
            # Name of the VHD or VHDX to use for VM creation. Must Exist in the
            # VMM Library            
            VHDName="TP5_14300_server.vhd"
            
            # Product key Can be blank if using a volume license VHD or VHDX, or you are
            #deploying in eval mode.  (Don't forget to press "skip" while VM creation).
            ProductKey="CNK65-Y6BBY-HCDPX-RVY2M-JK7JJ" 

            #Generation of VM to be used for deployment : Gen1 or Gen2
            Generation="Gen2"

            #Type of Deployment. The values are :
            #Standalone : For single Node 
            #Production : For 3-node
            DeploymentType="Production"	
			
			#Higly Available VM. Do you want the infrastructural VMs to be deployed on
			#Clustered Host and being higly Available ? If yes pass $true else $false
			HighlyAvailableVMs = $true
            
            #leave it if you want default IPvAddressType to be taken which is static
            # else change it to "Dynamic"
            IPv4AddressType=""
                        
            #Host Group to be Managed by Network Controller
            NCHostGroupName="NCManaged"
            
            #########################################################################
            #  Section to be filled if the Logical switch and Logical Network       #
            #  is already deployed for NC. You should do this if SET ( teamed)      #
            #  support is required. If you want VMM express to deploy the Logical   #
            #  switch and Management Network, skip this section.                    # 
            #  NOTE : This script assumes either you have both logical switch and   #
            # logical Network created and deployed or else you will use the script  #
            # to deploy both.                                                       #
            #########################################################################
            
            #Do you have an existing logical switch and the switch is deployed on all
            #the host you wish to Manage by NC
            IsLogicalSwitchDeployed = $true
            
            #if above is true give the name of logical switch			
            LogicalSwitch  = "Example_LS"

            # Do you have existing Management Network that you would like to use
            IsManagementVMNetworkExisting = $true

            #if above is true give the name of ManagementVMNetwork
            ManagementVMNetwork = "Example_LN" 

            #Uplink Port Profile to be used
            UplinkPortProfile = "Example_UPP"            
             
            #====================================================================================
            # The below set of Parameters are required for creation of Management Logical Network
            # and other Logical Networks Managed by NC.                                           
            # NOTE : If you already have Management Logical Network Created and switch deployed,
            # you don't need to specify any paramenet for "NC_Management" LN
            #====================================================================================
             LogicalNetworks = @(
			    @{
                    Name = "HNVPA"
                    Subnets = @(
                        @{
                            VLANID = 2017                                            #Example: 11
                            AddressPrefix = "10.10.10.0/23"                          #Example: "10.0.10.0/24"
                            DNS = @("10.177.16.161", "10.184.77.31", "10.184.77.32") #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = "10.10.56.1"                                  #Example: "10.0.10.1"
                            PoolStart = "10.10.56.10"                                #Example: "10.0.10.50"
                            PoolEnd = "10.10.56.29"                                  #Example: "10.0.10.150"
                       }
                    )
                },
				@{
                    Name = "Transit"
                    Subnets = @(
                        @{
                            VLANID = 562                                             #Example: 12
                            AddressPrefix = "10.20.110.0/23"                        #Example: "10.0.40.0/24"
                            DNS = @("10.177.16.161", "10.184.77.31")                 #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = "10.20.110.1"                                #Example: "10.0.40.1"
                            PoolStart = "10.20.111.10"                              #Example: "10.0.40.5"
                            PoolEnd = "10.20.111.29"                                #Example: "10.0.40.100"
                        }  
                    )
                }, 
                @{
                    #The first IP address (PoolStart) for this logical network is 
                    #automatically assigned to the SLB Manager.Other addresses such
                    #as the GatewayPublicIPAddress will start after that.
                    Name = "PublicVIP"
                    Subnets = @(
                        @{
                            VLANID = 0
                            AddressPrefix = "10.20.120.0/23"                        #Example: "10.0.20.0/24"
                            DNS = @("10.10.20.151")                                  #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = "10.184.120.10"                               #Example: "10.0.20.1"
                            PoolStart = "10.184.121.10"                              #Example: "10.0.20.5"
                            PoolEnd = "10.184.121.30"                                #Example: "10.0.20.100"
                            IsPublic = $true
                        }  
                    )
                },
                @{
                    #The first IP address (PoolStart) for this logical network is 
                    #automatically assigned to the SLB Manager.Other addresses such
                    #as the GatewayPublicIPAddress will start after that.
                    Name = "PrivateVIP"
                    Subnets = @(
                        @{
                            VLANID = 0
                            AddressPrefix = "10.40.150.0/23"                         #Example: "10.0.20.0/24"
                            DNS = @("10.10.21.151")                                   #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = "10.40.150.10"                                #Example: "10.0.20.1"
                            PoolStart = "10.40.151.10"                               #Example: "10.0.20.5"
                            PoolEnd = "10.40.151.30"                                 #Example: "10.0.20.100"
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
                            AddressPrefix = "10.30.150.0/23"                         #Example: "10.0.20.0/24"
                            DNS = @("10.10.21.151")                                #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = "10.30.150.1"                              #Example: "10.0.20.1"
                            PoolStart = "10.30.150.1"                             #Example: "10.0.20.5"
                            PoolEnd = "10.30.150.22"                               #Example: "10.0.20.100"
                            IsPublic = $false
                        }  
                    )
                },						
                @{
				    #if Management VM Network is not deployed give the ManagementVMNetwork information. Skip
                    # this if you already have this created.
                    Name = "NC_Management"
                    Subnets = @(
                    @{
                        VLANID = 561                                                  #Example: 7
                        AddressPrefix = "10.50.108.0/23"                             #Example: "10.0.0.0/24"
                        DNS = @("10.177.16.161", "10.184.77.31")                      #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                        Gateways = "10.50.108.1"                                     #Example: "10.0.40.1"
                        PoolStart = "10.50.109.51"                                   #Example: "10.0.0.5"
                        PoolEnd = "10.50.109.69"                                     #Example: "10.0.0.100"
                        ReservedIPset =  "10.50.109.61"                              #This IP will be used for NC Rest API                           
                    }  
                    )
                }

            )
								
            #=========================================================================================
            # The following set of paremeters are required for importing VMM service Template,
            # configuring the Service Template and Deploying the service Template.
            #==========================================================================================

            # Make this true if self signed certificate is to be used
            # Example : $True , $False
            IsCertSelfSigned = $true  

            #The password for server certificate. This sertificate will be installed on the Host
            ServerCertificatePassword="!!Password"	            

            # The following are service settings required for configuring and
            # deploying the service template imported client security Group Name
            ClientSecurityGroupName= "Example\Domain Users"

            # Local Admin credentials
            # The local admin user name will be .\Administrator
            LocalAdminPassword= "Password123!!"    

            # Management Domain Account Which will be used for NC Deployment
            ManagementDomainUser="ExampleLab\ExampleUser"
            ManagementDomainUserPassword="Password!!"

             # This is the domain which NC VMs will join
            ManagementDomainFDQN="Example.com"		

            #Managemet Security Group Name
            ManagementSecurityGroupName="ExampleLab\Example NC Management"


            
            # Prefix to be added to infrastructural VMs created. Put the prefix such
            # that it makes VM name unique as this is the machine name of VM and should be unique.            
            ComputerNamePrefix = "NCE"   

            RestName = "VMMExpress"
            
            ##################################
            #  Deoloyment Control Switches   #
            ##################################
                                    
            # Do you want to deploy NC
            DeployNC = $true
            
            #Do you want to Deploy SLB
            DeploySLB = $true  

            #Do you want to deploy GW. 
            DeployGW = $true  			
        };
           
     );
}
