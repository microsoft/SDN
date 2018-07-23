@{

    AllNodes = 
    @(
        @{ 
            NodeName="*"              # * indicates this section applies to all nodes.  Don't change it.
            
            InstallSrcDir="\\$env:Computername\SDNExpress"
            HostInstallSrcDir="\\$env:Computername\SDNExpress"
            
            #VM Creation variables
                        
            VHDName="14300.1003.amd64fre.rs1_release_svc_d.160410-1700_server_ServerDataCenter_en-us_vl.vhdx"
            ProductKey=""                                                                               

            #Update to a local path on the hyper-v hosts if local storage, or a UNC path for shared storage  
            VMLocation="C:\VM"                                        

            #User account with permission to add computers to the domain.  Username must not contain the domain.  
            DomainJoinUsername = 'AlYoung'                              
            DomainJoinPassword = 'V3ryC0mplex4dminP4ssword'             
            LocalAdminPassword = 'V3ryC0mplexP4ssword'                  

            #This is the FQDN that the Network Controller's REST IP is assigned to.
            #IMPORTANT: This name must be manually added to your DNS server and map to the NetworkControllerRestIP
            NetworkControllerRestName = "ncrest.$env:USERDNSDOMAIN"    #Example (after evaluation of $env:USERDNSDOMAIN): myname.contoso.com
            NetworkControllerRestIP = "10.184.108.4"                         #Example: 10.20.30.40
            NetworkControllerRestIPMask = "24"                     #Example: 24
           
            #This is the name of the virtual switch that must exist on each host.  Note: if you have any 
            #Hyper-V hosts which virtual switches that are named differently, you can override this variable
            #by adding it to the "HyperVHost" role nodes as needed.
            vSwitchName = "sdnSwitch"                                     

            #This is the user account and password that the Service Fabric cluster nodes will use for communicating with each other
            #The NCClusterUsername must contain the Domain name in the format DOMAIN\User
            NCClusterUsername = 'CONTOSO\AlYoung'        
            NCClusterPassword = 'MySuperS3cretP4ssword'  

            #This is the user account and password that is used for communicating with the Gateway VMs
            #The HostUsername must contain the Domain name in the format DOMAIN\User
            HostUsername = 'CONTOSO\al'                
            HostPassword = 'MySuperS3cretP4ssword'     
            
            #iDNS configuration - the iDNSAdminUsername must be a AD user who is a member of the DNSAdmins group. This can be same user as
            #the DomainJoinUsername above as long as they are also a member of DNSAdmins group. The iDNSAddress is the IP address of your DNS server
            #on the Management network and it must be an address which is reachable from the Network Controller nodes.
            iDNSAdminUsername = 'AlYoung'                                 #Example: "AlYoung"
            iDNSAdminPassword = 'V3ryC0mplex4dminP4ssword'                #Example: "V3ryC0mplex4dminP4ssword"
            iDNSAddress= '10.60.34.9'                                     #Example: "10.0.0.7"
            iDNSZoneName = 'contoso.local'                                #Example: "contoso.local"
            iDNSMacAddress = 'AA-BB-CC-AA-BB-CC'
            iDNSCredentialResourceId = 'c6abefg6-44fb-45f6-89ec-5ebd890a144f' 
            
            #Required for remotely setting cert file ACLs. This should not be changed.
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser = $true

            #This next section defines the logical networks that will be created in the network controller once it is deployed and running
            #The same subnet can be used for multiple logical networks as long as the PoolStart and PoolEnd do not overlap for any of them
            #If your networks are untagged/access mode networks with no VLAN, then specify VLANID of 0 for those networks.
            LogicalNetworks = @(
                @{
                    Name = "HNVPA"
                    ResourceId = 'bb6c6f28-bad9-441b-8e62-57d2be255904'
                    NetworkVirtualization = $true
                    Subnets = @(
                        @{
                            VLANID = "11" 
                            AddressPrefix = "10.10.56.0/23"        
                            DNS = @("10.184.108.9")             
                            Gateways = @("10.10.56.1")          
                            PoolStart = "10.10.56.100"          
                            PoolEnd = "10.10.56.150"            
                       }
                    )
                },    
                @{
                    Name = "PublicVIP"
                    ResourceId = 'f8f67956-3906-4303-94c5-09cf91e7e311'
                    Subnets = @(
                        @{
                            AddressPrefix = "41.40.40.0/27"         
                            Gateways = @("41.40.40.1")              
                            PoolStart = "41.40.40.2"                
                            PoolEnd = "41.40.40.8"                  
                            IsPublic = $true
                            IsVipPool = $true
                        }  
                    )
                },
                @{
                    #The first IP address (PoolStart) for this logical network is automatically assigned to the SLB Manager.  
                    Name = "PrivateVIP"
                    ResourceId = '0a386df6-5c5e-48bb-ab4b-709659aaa85a'
                    Subnets = @(
                        @{
                            AddressPrefix = "10.0.50.0/24"
                            Gateways = @("10.0.50.1")
                            PoolStart = "10.0.50.5"
                            PoolEnd = "10.0.50.100"
                            IsVipPool = $true
                        }
                    )
                },                
                @{
                    Name = "GreVIP"
                    ResourceId = 'f8f67956-3906-4303-94c5-09cf91e7e33'
                    Subnets = @(
                        @{  ## Gre GW's VIP Subnet
                            AddressPrefix = "10.90.0.0/24"                  
                            Gateways = @("10.90.0.1")                     
                            PoolStart = "10.90.0.100"                     
                            PoolEnd = "10.90.0.150"                       
                        }
                    )
                },
                @{
                    Name = "Transit"
                    ResourceId = '00000000-2222-1111-9999-000000000001'
                    Subnets = @(
                        @{
                            VLANID = "10"                         
                            AddressPrefix = "10.10.10.0/24"       
                            Gateways = @("10.10.10.1")            
                            PoolStart = "10.10.10.100"            
                            PoolEnd = "10.10.10.150"              
                        }  
                    )
                },    
                @{
                    Name = "Management"
                    ResourceId = '00000000-2222-1111-9999-000000000002'
                    Subnets = @(
                        @{
                            VLANID = "7"                        
                            AddressPrefix = "10.184.108.0/24"   
                            DNS = @("10.184.108.9")             
                            Gateways = @("10.184.108.1")        
                            PoolStart = "10.184.108.100"        
                            PoolEnd = "10.184.108.150"          
                        }  
                    )
                }
            )

            # Gateway Pool definitions
            # Do not modify
            GatewayPools = @(
                @{
                    ResourceId = "default"
                    Type = "All"
                    Capacity = "10000"				  
                    RedundantGatewayCount = "1"       
                },
                @{
                    ResourceId = "GrePool"
                    Type = "S2sGre"
                    Capacity = "10000"				  
                    RedundantGatewayCount = "1"       
                }
            )

            #This section defines the BGP Peer information.  This information is usually obtained from your physical 
            #switch configuration or must be provided to you by your network administrator.
            
            #This is used by the network controller only and does not need to be changed
            MuxPeerRouterName = 'BGPGateway-0'
            
            #MuxPeerRouterIP is typically the default gateway IP for the HNV PA network. 
            MuxPeerRouterIP = '10.10.56.1'                              
            
            #This is the ASN that is assigned to the physical router.  If BGP is used throughout your core network you must
            #coordinate with your network administrators to use an appropriate value.  If this is an island then you choose your
            #own values.
            MuxPeerRouterASN = '1'                             
            
            #This is the ASN that is assigned to the SLB MUXes and Gateways.  If BGP is used throughout your core network you must
            #coordinate with your network administrators to use an appropriate value.  The physical router must be configured
            #to accept peering connections from this ASN.
            MuxASN = '2'                                       

            #This section defines the BGP peerinf information for the GRE gateway.  If your BGP gateways use the same physical routers
            #as the muxes then you can use the same values, otherwise you will need to specify the values that are defined for the routers
            #that are serving the GRE gateways.
            GreBgpPeerRouterIP = '10.10.56.1'                  
            GreBgpPeerRouterASN = '1'                          
            GreBgpRouterASN = '3'                              
            
            #This is the public IP address that is assigned to the Site-to-site gateway pool.  It must come from the public VIP logical
            #network pool defined above.
            GatewayPublicIPAddress = "41.40.40.3"              

            #You generally don't need to change the rest of the values in this section

            VHDSrcLocation="Images"                                         #Must be under InstallSrcDir
            ToolsSrcLocation="Tools"                                        #Must be under InstallSrcDir
            CertFolder="Certs"                                              #Must be under InstallSrcDir
            NCCertName="NetworkControllerRootCertificate.cer"               #Will be generated on NC and placed in CertFolder

            #These are locations that exist on the hyper-v host or in VMs that will get created as needed
            MountDir="C:\Temp"                                                                
            ToolsLocation = "c:\Tools"

            VMMACAddressPoolStart = "00-1D-D8-00-00-00"
            VMMACAddressPoolEnd = "00-1D-D8-00-00-FF"

            MACAddressPoolStart = "00-1D-D8-B7-1C-00"
            MACAddressPoolEnd = "00-1D-D8-F4-1F-FF"

            #ResourceIDs that will be used.  These are global to the controller  
            NCCredentialResourceId = 'c6abefb6-24ab-45f6-80ec-5ebd690a544f'
            HostCredentialResourceId = 'b6a1d5d6-5e1a-4f63-982d-c3da2ad54ee2'
            MACAddressPoolResourceId = '8197fd09-8a69-417e-a55c-10c2c61f5ee7'
            PublicIPResourceId = '00000000-5555-0000-0001-000000000000'

            #By default this will use the same AD domain as the deployment machine.  Don't change this.
            FQDN=$env:USERDNSDOMAIN   

            #Version of this config file. Don't change this.
            ConfigFileVersion="1.2"
         },

        #You will define one node for each Hyper-V host in your environment.  A few are provided as examples, but 
        #you can add and remove them as needed.  If you remove nodes, you will need to reorganize the VMs sections so each
        #of the VMs you will be creating are assigned to a host.
        @{ 
            #This is the name of the first Hyper-V host to use for SDN workloads.  It does not include the FQDN.
            NodeName="Host1"                                   
            Role="HyperVHost"
            VMs=@(
              @{ 
                VMName="NC-01"                                     
				VMMemory=4GB                                       
                NICs=@(
                    @{
                        IPAddress="10.184.108.5"                   
                        LogicalNetwork = "Management"
                    }
                )
              },
              @{    
                VMName="MUX-01"                                         
				VMMemory=4GB                                            
                NICs=@(
                    @{
                        IPAddress="10.10.56.2"                           
                        LogicalNetwork = "HNVPA"
                    }
                )
              },
              @{ 
                VMName="MTGW-01"                                        
				VMMemory=4GB                                            
                VMRole = "Gateway"

                NICs=@(
                    @{
                        IPAddress="10.184.108.41"                      
                        LogicalNetwork = "Management"
                    }
                )
                
              }
            )
         },
         @{ 
            NodeName="Host2"                                      
            Role="HyperVHost"
            VMs=@(
              @{ 
                VMName="NC-02"                                           
				VMMemory=4GB                                             
                NICs=@(
                    @{
                        IPAddress="10.184.108.6"                         
                        LogicalNetwork = "Management"
                    }
                )
              },
              @{ 
                VMName="MUX-02"                                          
				VMMemory=4GB                                             
                NICs=@(
                    @{
                        IPAddress="10.10.56.3"
                        LogicalNetwork = "HNVPA"
                    }
                )
              },
              @{ 
                VMName="MTGW-02"                                       
				VMMemory=4GB                                           
                VMRole = "Gateway"

                NICs=@(
                    @{
                        IPAddress="10.184.108.42"                         
                        LogicalNetwork = "Management"
                    }
                )
              }
            )
         },
         @{ 
            NodeName="Host3"                                      
            Role="HyperVHost"
            VMs=@(
              @{ 
                VMName="NC-03"                                        
				VMMemory=4GB                                          
                NICs=@(
                    @{
                        IPAddress="10.184.108.7"                       
                        LogicalNetwork = "Management"
                    }
                )
              },
              @{ 
                VMName = "MTGW-03"
				VMMemory=4GB
                VMRole = "Gateway"

                NICs=@(
                    @{
                        IPAddress="10.184.108.43"                          
                        LogicalNetwork = "Management"
                    }
                )
                
              },
              @{ 
                VMName = "MTGW-04"
				VMMemory=4GB
                VMRole = "Gateway"

                NICs=@(
                    @{
                        IPAddress="10.184.108.44"                          
                        LogicalNetwork = "Management"
                    }
                )
              }			  
            )
         },
         @{ 
            NodeName="Host4"                                       
            Role="HyperVHost"
         },
         @{ 
            NodeName="NC-01"                                             
            Role="NetworkController"
         },
         @{ 
            NodeName="NC-02"                                           
            Role="NetworkController"
         },
         @{ 
            NodeName="NC-03"                                           
            Role="NetworkController"
         },
         @{ 
            NodeName="MUX-01"                                          
            Role="SLBMUX"
            InternalNicName = "HNVPA"
         },
         @{ 
            NodeName="MUX-02"                                          
            Role="SLBMUX"
            InternalNicName = "HNVPA"
         },         
         @{ 
            NodeName="MTGW-01"                                         
            Role     = "Gateway"
            GatewayPoolResourceId = "default"
            InternalNicName = "HNVPA"
            ExternalNicName = "Transit"

         },
         @{ 
            NodeName="MTGW-02"                                            
            Role     = "Gateway"
            GatewayPoolResourceId = "GrePool"
            InternalNicName = "HNVPA"
            ExternalNicName = "Transit"
         },
         @{  
            NodeName = "MTGW-03" 
            Role     = "Gateway" 
            GatewayPoolResourceId = "default" 
            InternalNicName = "HNVPA"
            ExternalNicName = "Transit"
         },
         @{  
            NodeName = "MTGW-04" 
            Role     = "Gateway" 
            GatewayPoolResourceId = "GrePool" 
            InternalNicName = "HNVPA"
            ExternalNicName = "Transit"
         }
     );
}
