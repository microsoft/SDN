@{
    AllNodes = 
    @(
        @{ 
            NodeName="*"                        # * indicates this section applies to all nodes.  Don't change it.
            
            InstallSrcDir="<< Shared Folder >>" # This directory will need to be created on the deployment host and shared (read/write) to Everyone

            #VM Creation variables
            VHDName="<< VHDX Image File >>"     # Name of the VHDX to use for VM creation. must exist in the images path under InstallSrcDir
            ProductKey=""                       # Can be blank if using a volume license, or you are deploying in eval mode.  (Don't forget to press "skip").

            VMLocation="<< Local Directory >>"  # Update to a local path on the hyper-v hosts if local storage, or a UNC path for shared storage

            DomainJoinUsername = '<< Domain Username >>'  # Indicate a domain account with permissions to add a machine to the domain
            DomainJoinPassword = '<< Domain Password >>'  # Indicate the password for the domain account
            LocalAdminPassword = '<< Local Password >>'   # Indicate the password for the local admin account (assumes it is the same on each Hyper-V Host)

            NetworkControllerRestName = "<< FQDN of Network Controller REST >>"  # HTTPS requires FQDN - This will be the HTTPS hostname to access REST API
            NetworkControllerRestIP = "<< Static Network Controller IP >>"       # Should be IP from Management Network - Make sure to create a Host A record in DNS for this IP to point to NetworkControllerRestName
            NetworkControllerRestIPMask = "<< Prefix Length >>"                  # Usually 24
            
            
            vSwitchName = "<< Name of the Hyper-V Switch >>" # Should be the same on each Hyper-V Host
            
            NCClusterUsername = "<< Domain Username >>" # Can be any domain-level account
            NCClusterPassword = "<< Domain Password >>" # Password to match the above            

            HostUsername = '<< Domain Username >>'      # Domain-level account with local admin on Hyper-V Hosts
            HostPassword = '<< Domain Password >>'      # Password to match the above

            LogicalNetworks = @(
                @{
                    Name = "HNVPA"                                      # Recommend this not change
                    ResourceId = 'bb6c6f28-bad9-441b-8e62-57d2be255904' # DO NOT CHANGE - Random GUID but value is referenced elsewhere
                    NetworkVirtualization = $true                       # DO NOT CHANGE - This Logical Network will host HNV overlay virtual networks
                    Subnets = @(
                        @{
                            VLANID = "<< VLAN ID >>"                    # This value must match the physical network configuration
                            AddressPrefix = "<< Subnet Prefix >>"       # This value must match the physical network configuration
                            DNS = @("<< DNS Server 1 >>", "<< DNS Server 2 >>") # These should match the DNS server(s) on your management network
                            Gateways = @("<< Default Gateway >> ")      # This IP address must be assigned on the physical network to the SVI on a ToR or BGP VM
                            PoolStart = "<< IP Address >>"              # This value must be an IP within the AddressPrefix
                            PoolEnd = "<< IP Address >> "               # This value must be an IP within the AddressPrefix and greater than the PoolStart IP
                       }
                    )
                },    
                @{
                    Name = "VIP"                                        # Recommend this not change
                    ResourceId = 'f8f67956-3906-4303-94c5-09cf91e7e311' # DO NOT CHANGE - Random GUID but value is referenced elsewhere
                    Subnets = @(
                        @{
                            AddressPrefix = "<< Subnet Prefix >>"       # This value must match the physical network configuration"
                            DNS = @("<< DNS Server 1 >>", "<< DNS Server 2 >>") # These should match the DNS server(s) on your management network
                            Gateways = @("<< Default Gateway >> ")      # This IP address must be assigned on the physical network to the SVI on a ToR or BGP VM
                            PoolStart = "<< IP Address >>"              # This value must be an IP within the AddressPrefix
                            PoolEnd = "<< IP Address >> "               # This value must be an IP within the AddressPrefix and greater than the PoolStart IP
                            IsPublic = $true                            # This is a publicly accessible VIP address
                        }  
                    )
                },    
                @{
                    Name = "Transit"                                    # Recommend this not change - Reserved for future use
                    ResourceId = '00000000-2222-1111-9999-000000000001' # DO NOT CHANGE - Random GUID but value is referenced elsewhere
                    Subnets = @(
                        @{
                            VLANID    = "<< VLAN ID >>"                 # This value must match the physical network configuration"
                            AddressPrefix    = "<< Subnet Prefix >>"    # This value must match the physical network configuration"
                            DNS       = @("<< DNS Server 1 >>", "<< DNS Server 2 >>") # These should match the DNS server(s) on your management network
                            Gateways  = @("<< Default Gateway >> ")     # This IP address must be assigned on the physical network to the SVI on a ToR or BGP VM
                            PoolStart = "<< IP Address >>"              # This value must be an IP within the AddressPrefix
                            PoolEnd   = "<< IP Address >> "             # This value must be an IP within the AddressPrefix and greater than the PoolStart IP
                        }  
                    )
                },    
                @{
                    Name = "Management"                                 # Recommend this not change
                    ResourceId = '00000000-2222-1111-9999-000000000002' # DO NOT CHANGE - Random GUID but value is referenced elsewhere
                    Subnets = @(
                        @{
                            VLANID = "<< VLAN ID >>"                    # This value must match the physical network configuration"
                            AddressPrefix = "<< Subnet Prefix >>"       # This value must match the physical network configuration"
                            DNS = @("<< DNS Server 1 >>", "<< DNS Server 2 >>") # These should match the DNS server(s) on your management network
                            Gateways = @("<< Default Gateway >> ")      # This IP address must be assigned on the physical network to the SVI on a ToR or BGP VM
                            PoolStart = "<< IP Address >>"              # This value must be an IP within the AddressPrefix
                            PoolEnd = "<< IP Address >> "               # This value must be an IP within the AddressPrefix and greater than the PoolStart IP
                        }  
                    )
                }


            )

            MuxPeerRouterName = '<< BGP Peer >> '   # Arbitrary name (does not need to be registered in DNS
            MuxPeerRouterIP = '<< IP Address >>'    # This is generally the same value as the PA Logical Network Gateway above
            MuxPeerRouterASN = '<< BGP Peer ASN >>' # Remote ASN of the Peer BGP Router 
            MuxASN = '<< SLB MUX ASN >>'            # Local ASN of the SLB MUX

            #You generally don't need to change the rest of the values in this section

            VHDSrcLocation="Images"                                         # Must create this directory under InstallSrcDir if it doesn't exist
            ToolsSrcLocation="Tools"                                        # Must create this directory under InstallSrcDir if it doesn't exist
            CertFolder="Certs"                                              # Must create this directory under InstallSrcDir if it doesn't exist
            NCCertName="NetworkControllerRootCertificate.cer"               # Will be generated on NC and placed in CertFolder

            #These are locations that exist on the hyper-v host or in VMs that will get created as needed
            MountDir="C:\Temp"                                                                
            ToolsLocation = "c:\Tools"

            MACAddressPoolStart = "00-1D-D8-B7-1C-00" # You generally don't need to change this - used internally by NC for Infrastructure MACs on Hyper-V Host
            MACAddressPoolEnd = "00-1D-D8-F4-1F-FF"   # You generally don't need to change this - used internally by NC for Infrastructure MACs on Hyper-V Host

            #ResourceIDs that will be used.  These are global to the controller  
            NCCredentialResourceId = 'c6abefb6-24ab-45f6-80ec-5ebd690a544f'   # DO NOT CHANGE
            HostCredentialResourceId = 'b6a1d5d6-5e1a-4f63-982d-c3da2ad54ee2' # DO NOT CHANGE
            MACAddressPoolResourceId = '8197fd09-8a69-417e-a55c-10c2c61f5ee7' # DO NOT CHANGE

            #By default this will use the same AD domain as the deployment machine.  Don't change this.
            FQDN=$env:USERDNSDOMAIN   

         },
        @{ 
            NodeName="<< Host Name >>"                 # Hyper-V Host Name (not FQDN) - All VMs underneath will be deployed on this host
            Role="HyperVHost"
            VMs=@(
              @{ 
                VMName="TP4NC-01"                      # Name of the first Network Controller node - this can be changed if desired
                NICs=@(
                    @{
                        Name="Management"              # Name of the Network Adapter in the VM (NIC attaches to Management network)
                        IPAddress="<< IP Adddress >>"  # Static IP of Network Adapter in the VM taken from the managmement subnet prefix (this may be overwritten if DHCP is used)
                        LogicalNetwork = "Management"  # DO NOT CHANGE - Name of the logical network to which this adapter attaches (specified above)

                        #Do not change these values for the network controller
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=1
                    }
                )
              },
              @{ 
                VMName="TP4MUX-01"                     # Name of the first SLB MUX - this can be changed if desired
                NICs=@(
                    @{
                        Name="HNVPA"                   # Name of the Network Adapter in the VM (NIC attaches to PA network)
                        IPAddress="<< IP Address >>"   # This IP needs to be within the subnet prefix of the PA Network specified above       
                        LogicalNetwork = "HNVPA"       # DO NOT CHANGE - Name of the logical network to which this adapter attaches

                        #Do not change these values for the SLB MUX
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
              }
            )
         },
         @{ 
            NodeName="<< Host Name >>"                 # Hyper-V Host Name (not FQDN) - All VMs underneath will be deployed on this host
            Role="HyperVHost"
            VMs=@(
              @{ 
                VMName="TP4NC-02"                      # Name of the second Network Controller node - this can be changed if desired
                NICs=@(
                    @{
                        Name="Management"              # Name of the Network Adapter in the VM (NIC attaches to Management network)
                        IPAddress="<< IP Adddress >>"  # Static IP of Network Adapter in the VM taken from the Management subnet prefix (this may be overwritten if DHCP is used)
                        LogicalNetwork = "Management"  # DO NOT CHANGE - Name of the logical network to which this adapter attaches (specified above)

                        #Do not change these values for the network controller
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=1
                    }
                )
              },
              @{ 
                VMName="TP4MUX-02"
                NICs=@(
                    @{
                        Name="HNVPA"                   # Name of the Network Adapter in the VM (NIC attaches to PA network)
                        IPAddress="<< IP Address >>"   # This IP needs to be within the subnet prefix of the PA Network specified above
                        LogicalNetwork = "HNVPA"       # DO NOT CHANGE - Name of the logical network to which this adapter attaches

                        #Do not change these values for the SLB MUX
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=2
                    }
                )
              }
            )
         },

         @{ 
            NodeName="<< Host Name >>"                 # Hyper-V Host Name (not FQDN) - All VMs underneath will be deployed on this host
            Role="HyperVHost"
            VMs=@(
              @{             
                VMName="TP4NC-03"                      # Name of the third Network Controller node - this can be changed if desired
                NICs=@(
                    @{
                        Name="Management"              # Name of the Network Adapter in the VM (NIC attaches to Management network)
                        IPAddress="<< IP Adddress >>"  # Static IP of Network Adapter in the VM taken from the Management subnet prefix (this may be overwritten if DHCP is used)
                        LogicalNetwork = "Management"  # DO NOT CHANGE - Name of the logical network to which this adapter attaches (specified above)

                        #Do not change these values for the network controller
                        PortProfileID="00000000-0000-0000-0000-000000000000"
                        PortProfileData=1
                    }
                )
              }
            )
         },
         <#
         @{ # Add more Hyper-V Hosts if desired
            NodeName="<< Host Name >>"
            Role="HyperVHost"
         },
         #>
         @{ 
            NodeName="TP4NC-01"                                            # Network Controller Node VM - Needs to match name from above
            Role="NetworkController"                                       # DO NOT CHANGE
            ServiceFabricRingMembers=@("TP4NC-01", "TP4NC-02", "TP4NC-03") # Add all Network Controller Node VMs to this list           
         },
          @{ 
            NodeName="TP4NC-02"       # Install the Network Controller role on this VM - needs to match name from above
            Role="NetworkController"
         },
          @{ 
            NodeName="TP4NC-03"       # Install the Network Controller role on this VM - needs to match name from above
            Role="NetworkController"
         },
         @{ 
            NodeName="TP4MUX-01"      # Install the SLB MUX on this VM - needs to match name from above
            Role="SLBMUX"
            
            #These resource ids are one per mux
            MuxVirtualServerResourceId = 'd2b75161-ec7d-4141-8653-39ab194a2291' # DO NOT CHANGE - Random GUID referenced elsewhere
            MuxResourceId = '86c0a59c-4ffe-4b12-847c-641291fb465c'              # DO NOT CHANGE - Random GUID referenced elsewhere
         },
         @{ 
            NodeName="TP4MUX-02"      # Install the SLB MUX on this VM - needs to match name from above
            Role="SLBMUX"

            #These resource ids are one per mux
            MuxVirtualServerResourceId = 'a3f1b6a0-d0e7-46a0-85a2-354f44a8cfce' # DO NOT CHANGE - Random GUID referenced elsewhere
            MuxResourceId = '97bb1718-3bf4-4264-bd6a-4438a932af0a'              # DO NOT CHANGE - Random GUID referenced elsewhere
         }
     );
}