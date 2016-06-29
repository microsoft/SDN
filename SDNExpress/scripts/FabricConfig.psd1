@{

    AllNodes = 
    @(
        @{ 
            NodeName="*"              # * indicates this section applies to all nodes.  Don't change it.
            
            InstallSrcDir="\\$env:Computername\SDNExpress"

            #VM Creation variables
                        
            VHDName="<< Replace >>"    # Name of the VHDX to use for VM creation. must exist in the images path under InstallSrcDir
            ProductKey=""                                                                               # Can be blank if using a volume license, or you are deploying in eval mode.  (Don't forget to press "skip").

            #Update to a local path on the hyper-v hosts if local storage, or a UNC path for shared storage  
            VMLocation="<< Replace >>"                                        #Example: "C:\ClusterStorage\Volume1\VMs"

            #User account with permission to add computers to the domain.  Username must not contain the domain.  
            DomainJoinUsername = '<< Replace >>'                              #Example: "AlYoung"
            DomainJoinPassword = '<< Replace >>'                              #Example: "V3ryC0mplex4dminP4ssword"
            LocalAdminPassword = '<< Replace >>'                              #Example: "V3ryC0mplexP4ssword"

            #This is the FQDN that the Network Controller's REST IP is assigned to.
            #IMPORTANT: This name must be manually added to your DNS server and map to the NetworkControllerRestIP
            NetworkControllerRestName = "<< Replace >>.$env:USERDNSDOMAIN"    #Example (after evaluation of $env:USERDNSDOMAIN): myname.contoso.com
            NetworkControllerRestIP = "<< Replace >>"                         #Example: 10.20.30.40
            NetworkControllerRestIPMask = "<< Replace >>"                     #Example: 24
           
            #This is the name of the virtual switch that must exist on each host.  Note: if you have any 
            #Hyper-V hosts which virtual switches that are named differently, you can override this variable
            #by adding it to the "HyperVHost" role nodes as needed.
            vSwitchName = "<< Replace >>"                                     #Example: SDNSwitch

            #This is the user account and password that the Service Fabric cluster nodes will use for communicating with each other
            #The NCClusterUsername must contain the Domain name in the format DOMAIN\User
            NCClusterUsername = '<< Replace >>'                               #Example: CONTOSO\AlYoung
            NCClusterPassword = '<< Replace >>'                               #Example: MySuperS3cretP4ssword

            #This is the user account and password that is used for communicating with the Gateway VMs
            #The HostUsername must contain the Domain name in the format DOMAIN\User
            HostUsername = '<< Replace >>'                                    #Example: CONTOSO\al
            HostPassword = '<< Replace >>'                                    #Example: MySuperS3cretP4ssword


            #iDNS IP address and resource ID. The creds are same as the domain creds
            iDNSCredentialResourceId = "c6abefg6-44fb-45f6-89ec-5ebd890a144f"            
            iDNSAddress= '<< Replace >>'                                      #Example: "10.0.0.7"
            iDNSZoneName = '<< Replace >>'                                    #Example: "contoso.local"
            DnsPort=53                                                        #Standard DNS port. DO NOT CHANGE            
            DnsIPAddress="169.254.169.254"                                    #Fixed IP address understood by DNS proxy. DO NOT CHANGE
            DnsProxyServiceName="DnsProxy"                                    #Name of the service. DO NOT CHANGE
            iDNSMacAddress = '<< Replace >>'                                  #Example "AA-BB-CC-AA-BB-CC"

            #iDNS Proxy Registry Hives
            iDnsVfpPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\DnsProxyService"                                                                                          
            iDnsProxyPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNSProxy\Parameters"
            

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
                            VLANID = "<< Replace >>"                          #Example: 11
                            AddressPrefix = "<< Replace >>"                   #Example: "10.0.10.0/24"
                            DNS = @("<< Replace >>")                          #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = @("<< Replace >>")                     #Example: @("10.0.10.1")
                            PoolStart = "<< Replace >>"                       #Example: "10.0.10.50"
                            PoolEnd = "<< Replace >>"                         #Example: "10.0.10.150"
                       }
                    )
                },    
                @{
                    #The first IP address (PoolStart) for this logical network is automatically assigned to the SLB Manager.  
                    #Other addresses such as the GatewayPublicIPAddress will start after that.
                    Name = "VIP"
                    ResourceId = 'f8f67956-3906-4303-94c5-09cf91e7e311'
                    Subnets = @(
                        @{
                            AddressPrefix = "<< Replace >>"                   #Example: "10.0.20.0/24"
                            DNS = @("<< Replace >>")                          #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = @("<< Replace >>")                     #Example: @("10.0.20.1")
                            PoolStart = "<< Replace >>"                       #Example: "10.0.20.5"
                            PoolEnd = "<< Replace >>"                         #Example: "10.0.20.100"
                            IsPublic = $true
                            IsVIP = $true
                        }  
                    )
                },
                @{
                    Name = "GreVIP"
                    ResourceId = 'f8f67956-3906-4303-94c5-09cf91e7e33'
                    Subnets = @(
                        @{  ## Gre GW's VIP Subnet
                            AddressPrefix = "<< Replace >>"                   #Example: "10.0.30.0/24"
                            DNS = @("<< Replace >>")                          #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = @("<< Replace >>")                     #Example: @("10.0.30.1")
                            PoolStart = "<< Replace >>"                       #Example: "10.0.30.5"
                            PoolEnd = "<< Replace >>"                         #Example: "10.0.30.100"
                        }
                    )
                },
                @{
                    Name = "Transit"
                    ResourceId = '00000000-2222-1111-9999-000000000001'
                    Subnets = @(
                        @{
                            VLANID = "<< Replace >>"                          #Example: 12
                            AddressPrefix = "<< Replace >>"                   #Example: "10.0.40.0/24"
                            DNS = @("<< Replace >>")                          #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = @("<< Replace >>")                     #Example: @("10.0.40.1")
                            PoolStart = "<< Replace >>"                       #Example: "10.0.40.5"
                            PoolEnd = "<< Replace >>"                         #Example: "10.0.40.100"
                        }  
                    )
                },    
                @{
                    Name = "Management"
                    ResourceId = '00000000-2222-1111-9999-000000000002'
                    Subnets = @(
                        @{
                            VLANID = "<< Replace >>"                          #Example: 7
                            AddressPrefix = "<< Replace >>"                   #Example: "10.0.0.0/24"
                            DNS = @("<< Replace >>")                          #Example: @("10.0.0.7", "10.0.0.8", "10.0.0.9")
                            Gateways = @("<< Replace >>")                     #Example: @("10.0.40.1")
                            PoolStart = "<< Replace >>"                       #Example: "10.0.0.5"
                            PoolEnd = "<< Replace >>"                         #Example: "10.0.0.100"
                            IsVIP = $true                             
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
                    Capacity = "10000"				    #Example: 10000000 # for 10 GB
                    RedundantGatewayCount = "1"                   #Example: 2        # for 2 Redundant Gateways
                },
                @{
                    ResourceId = "MyGrePool"
                    Type = "S2sGre"
                    Capacity = "10000"				    #Example: 10000000 # for 10 GB
                    RedundantGatewayCount = "1"                   #Example: 2        # for 2 Redundant Gateways
                },
                @{
                    ResourceId = "MyIPSecPool"
                    Type = "S2sIPSec"
                    Capacity = "10000"				    #Example: 10000000 # for 10 GB
                    RedundantGatewayCount = "1"                   #Example: 2        # for 2 Redundant Gateways
                }
            )

            #This section defines the BGP Peer information.  This information is usually obtained from your physical 
            #switch configuration or must be provided to you by your network administrator.
            
            #This is used by the network controller only and does not need to be changed
            MuxPeerRouterName = 'BGPGateway-0'
            
            #MuxPeerRouterIP is typically the default gateway IP for the HNV PA network. 
            MuxPeerRouterIP = '<< Replace >>'                                #Example: "10.0.10.1"
            
            #This is the ASN that is assigned to the physical router.  If BGP is used throughout your core network you must
            #coordinate with your network administrators to use an appropriate value.  If this is an island then you choose your
            #own values.
            MuxPeerRouterASN = '<< Replace >>'                               #Example: "1"
            
            #This is the ASN that is assigned to the SLB MUXes and Gateways.  If BGP is used throughout your core network you must
            #coordinate with your network administrators to use an appropriate value.  The physical router must be configured
            #to accept peering connections from this ASN.
            MuxASN = '2'                                         #Example: "2"

            #This section defines the BGP peerinf information for the GRE gateway.  If your BGP gateways use the same physical routers
            #as the muxes then you can use the same values, otherwise you will need to specify the values that are defined for the routers
            #that are serving the GRE gateways.
            GreBgpPeerRouterIP = '<< Replace >>'                              #Example: "10.0.10.1"
            GreBgpPeerRouterASN = '<< Replace >>'                             #Example: "1"
            GreBgpRouterASN = '<< Replace >>'                                 #Example: "2"
            
            #This is the public IP address that is assigned to the Site-to-site gateway pool.  It must come from the public VIP logical
            #network pool defined above.
            GatewayPublicIPAddress = "<< Replace >>"                          #Example: 10.0.20.6

            #You generally don't need to change the rest of the values in this section

            VHDSrcLocation="Images"                                         #Must be under InstallSrcDir
            ToolsSrcLocation="Tools"                                        #Must be under InstallSrcDir
            CertFolder="Certs"                                              #Must be under InstallSrcDir
            NCCertName="NetworkControllerRootCertificate.cer"               #Will be generated on NC and placed in CertFolder

            #These are locations that exist on the hyper-v host or in VMs that will get created as needed
            MountDir="C:\Temp"                                                                
            ToolsLocation = "c:\Tools"

            MACAddressPoolStart = "00-1D-D8-B7-1C-00"
            MACAddressPoolEnd = "00-1D-D8-F4-1F-FF"

            #ResourceIDs that will be used.  These are global to the controller  
            NCCredentialResourceId = 'c6abefb6-24ab-45f6-80ec-5ebd690a544f'
            HostCredentialResourceId = 'b6a1d5d6-5e1a-4f63-982d-c3da2ad54ee2'
            MACAddressPoolResourceId = '8197fd09-8a69-417e-a55c-10c2c61f5ee7'
            PublicIPResourceId = '00000000-5555-0000-0001-000000000000'

            #By default this will use the same AD domain as the deployment machine.  Don't change this.
            FQDN=$env:USERDNSDOMAIN   

         },

        #You will define one node for each Hyper-V host in your environment.  A few are provided as examples, but 
        #you can add and remove them as needed.  If you remove nodes, you will need to reorganize the VMs sections so each
        #of the VMs you will be creating are assigned to a host.
        @{ 
            #This is the name of the first Hyper-V host to use for SDN workloads.  It does not include the FQDN.
            NodeName="<< Replace >>"                                        #Example: "Host-01"
            Role="HyperVHost"
            VMs=@(
              @{ 
                VMName="NC-01"                                      #Example: "NC-01"
				VMMemory=4GB                                        #Example: 4GB
                NICs=@(
                    @{
                        Name="Management"
                        IPAddress="<< Replace >>"                           #Example: "10.0.0.10"
                        LogicalNetwork = "Management"

                        #Static MAC address to use for the VM. 
                        #Change this if it will collide with machineson the same network segment.
                        MacAddress="001DC8000101"                         #Example: "001DC8000001"

                        #Do not change these values for the network controller
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=1
                    }
                )
              },
              @{    
                VMName="MUX-01"                                           #Example: "MUX-01"
				VMMemory=4GB                                              #Example: 4GB
                NICs=@(
                    @{
                        Name="HNVPA"
                        IPAddress="<< Replace >>"                           #Example: "10.0.10.10"
                        LogicalNetwork = "HNVPA"
                        MacAddress="001DC8000102"

                        #Do not change these values for the SLB MUX
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
              },
              @{ 
                VMName="MTGW-01"                                          #Example: "MTGW-01"
				VMMemory=4GB                                              #Example: 4GB
                VMRole = "Gateway"

                NICs=@(
                    @{
                        Name="Management"
                        IPAddress="<< Replace >>"                           #Example: "10.0.0.11"
                        LogicalNetwork = "Management"
                        MacAddress="001DC8000103"

                        #Do not change these values
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
                
                InternalNicPortProfileId = "00000000-3333-0000-0000-000000000001"
                ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000001"
                InternalNicMac = "002011111101"
                ExternalNicMac = "002011111102"

                #This must match the VLAN ID for the transit network as defined in the logical networks section
                ExternalVlanId = "<< Replace >>"                            #Example: 10              
              },
              @{ 
                VMName="MTGW-04"                                          #Example: "MTGW-01"
				VMMemory=4GB                                              #Example: 4GB
                VMRole = "Gateway"

                NICs=@(
                    @{
                        Name="Management"
                        IPAddress="<< Replace >>"                           #Example: "10.0.0.11"
                        LogicalNetwork = "Management"
                        MacAddress="001DC8000104"

                        #Do not change these values
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
                
                InternalNicPortProfileId = "00000000-3333-0000-0000-000000000004"
                ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000004"
                InternalNicMac = "002011111107"
                ExternalNicMac = "002011111108"

                #This must match the VLAN ID for the transit network as defined in the logical networks section
                ExternalVlanId = "<< Replace >>"                            #Example: 10              
              }
            )
         },
         @{ 
            NodeName="<< Replace >>"                                        #Example: "Host-02"
            Role="HyperVHost"
            VMs=@(
              @{ 
                VMName="NC-02"                                            #Example: "NC-02"
				VMMemory=4GB                                              #Example: 4GB
                NICs=@(
                    @{
                        Name="Management"
                        IPAddress="<< Replace >>"                           #Example: "10.0.0.12"
                        LogicalNetwork = "Management"

                        #Static MAC address to use for the VM. 
                        #Change this if it will collide with machineson the same network segment.
                        MacAddress="001DC8000201"                         #Example: "001DC8000001"

                        #Do not change these values for the network controller
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=1
                    }
                )
              },
              @{ 
                VMName="MUX-02"                                           #Example: "MUX-02"
				VMMemory=4GB                                              #Example: 4GB
                NICs=@(
                    @{
                        Name="HNVPA"
                        IPAddress="<< Replace >>"
                        LogicalNetwork = "HNVPA"
                        MacAddress="001DC8000202"

                        #Do not change these values for the SLB MUX
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
              },
              @{ 
                VMName="MTGW-02"                                          #Example: "MTGW-02"
				VMMemory=4GB                                              #Example: 4GB
                VMRole = "Gateway"

                NICs=@(
                    @{
                        Name="Management"
                        IPAddress="<< Replace >>"                           #Example: "10.0.0.13"
                        LogicalNetwork = "Management"
                        MacAddress="001DC8000203"

                        #Do not change these values
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
                
                InternalNicPortProfileId = "00000000-3333-0000-0000-000000000002"
                ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000002"
                InternalNicMac = "002011111103"
                ExternalNicMac = "002011111104"

                #This must match the VLAN ID for the transit network as defined in the logical networks section
                ExternalVlanId = "<< Replace >>"                            #Example: 10
              },
              @{ 
                VMName="MTGW-05"                                          #Example: "MTGW-02"
				VMMemory=4GB                                              #Example: 4GB
                VMRole = "Gateway"

                NICs=@(
                    @{
                        Name="Management"
                        IPAddress="<< Replace >>"                           #Example: "10.0.0.13"
                        LogicalNetwork = "Management"
                        MacAddress="001DC8000204"

                        #Do not change these values
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
                
                InternalNicPortProfileId = "00000000-3333-0000-0000-000000000005"
                ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000005"
                InternalNicMac = "002011111109"
                ExternalNicMac = "00201111110A"

                #This must match the VLAN ID for the transit network as defined in the logical networks section
                ExternalVlanId = "<< Replace >>"                            #Example: 10
              }
            )
         },
         @{ 
            NodeName="<< Replace >>"                                        #Example: "Host-03"
            Role="HyperVHost"
            VMs=@(
              @{ 
                VMName="NC-03"                                            #Example: "NC-03"
				VMMemory=4GB                                              #Example: 4GB
                NICs=@(
                    @{
                        Name="Management"
                        IPAddress="<< Replace >>"                           #Example: "10.0.0.14"
                        LogicalNetwork = "Management"
                        MacAddress="001DC8000301"

                        #Do not change these values for the network controller
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=1
                    }
                )
              },
              @{ 
                VMName = "MTGW-03"
				VMMemory=4GB
                VMRole = "Gateway"

                NICs=@(
                    @{
                        Name="Management"
                        IPAddress="<< Replace >>"                           #Example: "10.0.0.15"
                        LogicalNetwork = "Management"
                        MacAddress="001DC8000302"

                        #Do not change these values 
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
                
                InternalNicPortProfileId = "00000000-3333-0000-0000-000000000003"
                ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000003"
                InternalNicMac = "002011111105"
                ExternalNicMac = "002011111106"

                #This must match the VLAN ID for the transit network as defined in the logical networks section
                ExternalVlanId = "<< Replace >>"                            #Example: 10
              },
              @{ 
                VMName = "MTGW-06"
				VMMemory=4GB
                VMRole = "Gateway"

                NICs=@(
                    @{
                        Name="Management"
                        IPAddress="<< Replace >>"                           #Example: "10.0.0.15"
                        LogicalNetwork = "Management"
                        MacAddress="001DC8000303"

                        #Do not change these values 
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
                
                InternalNicPortProfileId = "00000000-3333-0000-0000-000000000006"
                ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000006"
                InternalNicMac = "00201111110B"
                ExternalNicMac = "00201111110C"

                #This must match the VLAN ID for the transit network as defined in the logical networks section
                ExternalVlanId = "<< Replace >>"                            #Example: 10
              }			  
            )
         },
        @{ 
            NodeName="<< Replace >>"                                        #Example: "Host-04"
            Role="HyperVHost"
         },
         # You can add more Nodes (physical servers) below using the same format

         @{ 
            NodeName="NC-01"                                              #Example: "NC-01"
            Role="NetworkController"
            ServiceFabricRingMembers=@("NC-01", "NC-02", "NC-03")         #Example: @("NC-01", "NC-02", "NC-03")
         },
         @{ 
            NodeName="NC-02"                                              #Example: "NC-02"
            Role="NetworkController"
         },
         @{ 
            NodeName="NC-03"                                              #Example: "NC-03"
            Role="NetworkController"
         },
         @{ 
            NodeName="MUX-01"                                             #Example: "MUX-01"
            Role="SLBMUX"
            MuxVirtualServerResourceId="MUX-01"                           #Example: "MUX-01"
            MuxResourceId="MUX-01"                                        #Example: "MUX-01"
         },
         @{ 
            NodeName="MUX-02"                                             #Example: "MUX-02"
            Role="SLBMUX"
            MuxVirtualServerResourceId="MUX-02"                           #Example: "MUX-02"
            MuxResourceId="MUX-02"                                        #Example: "MUX-02"
         },         
         @{ 
            NodeName="MTGW-01"                                            #Example: "MTGW-01"
            Role     = "Gateway"
            GatewayPoolResourceId = "default"

            InternalNicPortProfileId = "00000000-3333-0000-0000-000000000001"
            ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000001"
            InternalNicMac = "002011111101"
            ExternalNicMac = "002011111102"
            ExternalIPAddress = "<< Replace >>"                             #Example: "10.0.40.5"
         },
         @{ 
            NodeName="MTGW-02"                                            #Example: "MTGW-02"
            Role     = "Gateway"
            GatewayPoolResourceId = "default"

            InternalNicPortProfileId = "00000000-3333-0000-0000-000000000002"
            ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000002"
            InternalNicMac = "002011111103"
            ExternalNicMac = "002011111104"                
            ExternalIPAddress = "<< Replace >>"                             #Example: "10.0.40.6"
         },
         @{  
            NodeName = "MTGW-03" 
            Role     = "Gateway" 
            GatewayPoolResourceId = "MyGrePool" 

            InternalNicPortProfileId = "00000000-3333-0000-0000-000000000003" 
            ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000003" 
            InternalNicMac = "002011111105" 
            ExternalNicMac = "002011111106"                 
            ExternalIPAddress = "<< Replace >>"                             #Example: "10.0.40.7" 
         },         
         @{ 
            NodeName="MTGW-04"                                            #Example: "MTGW-01"
            Role     = "Gateway"
            GatewayPoolResourceId = "MyGrePool"

            InternalNicPortProfileId = "00000000-3333-0000-0000-000000000004"
            ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000004"
            InternalNicMac = "002011111107"
            ExternalNicMac = "002011111108"
            ExternalIPAddress = "<< Replace >>"                             #Example: "10.0.40.5"
         },
         @{ 
            NodeName="MTGW-05"                                            #Example: "MTGW-02"
            Role     = "Gateway"
            GatewayPoolResourceId = "MyIPSecPool"

            InternalNicPortProfileId = "00000000-3333-0000-0000-000000000005"
            ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000005"
            InternalNicMac = "002011111109"
            ExternalNicMac = "00201111110A"                
            ExternalIPAddress = "<< Replace >>"                             #Example: "10.0.40.6"
         },
         @{  
            NodeName = "MTGW-06" 
            Role     = "Gateway" 
            GatewayPoolResourceId = "MyIPSecPool" 

            InternalNicPortProfileId = "00000000-3333-0000-0000-000000000006" 
            ExternalNicPortProfileId = "00000000-3333-0000-1111-000000000006" 
            InternalNicMac = "00201111110B" 
            ExternalNicMac = "00201111110C"                 
            ExternalIPAddress = "<< Replace >>"                             #Example: "10.0.40.7" 
         }
     );
}
