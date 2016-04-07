@{
    AllNodes = 
    @(
        @{ 
            NodeName="*"                                                    # * indicates this section applies to all nodes.  Don't change it.

            InstallSrcDir="\\$env:Computername\SDNExpress"

            #VM Creation variables
                        
            VHDName="10586.0.amd64fre.th2_release.151029-1700_server_ServerDataCenter_en-us_vl.vhdx"    # Name of the VHDX to use for VM creation. must exist in the images path under InstallSrcDir
            ProductKey=""                                                                               # Can be blank if using a volume license, or you are deploying in eval mode.  (Don't forget to press "skip").

            #Update to a local path on the hyper-v hosts if local storage, or a UNC path for shared storage  
            VMLocation="<<Replace>>"                                        #Example: "C:\ClusterStorage\Volume1\VMs"

            # Local administrator credentials for the newly created VMs.
            LocalAdminUsername = ".\Administrator"
            LocalAdminPassword = '<<Replace>>'                              #Example: "V3ryC0mplexP4ssword"

            TenantName = "<<Replace>>"                                      #Example: "Contoso"

            #You generally don't need to change the rest of the values in this section

            #Source Files
            VHDSrcLocation="Images"                                         # Must be under InstallSrcDir

            #These are locations that exist on the hyper-v host or in VMs that will get created as needed
            MountDir="C:\Temp"                                                                

         },
        @{ 
            NodeName="<<Replace>>"                                        #Example: "Host-04"
            Role="HyperVHost"
            VMs=@(
                @{ 
                  # Computer Name to be assigned to the Enterprise GW used for IPSec S2S VPN
                  VMName = "IPSecGW01"
                  VMMemory=4GB                                          #Example: 4GB
                  PortProfileID = "00000000-0000-0000-0000-000000000000"
                  
                  # Enterprise Gateway's Internet /DMZ IP Address and network details
                  IPAddress   = "<<Replace>>"                             #Example: "10.127.134.121"
                  Mask        = "<<Replace>>"                             #Example: 25
                  Gateway     = "<<Replace>>"                             #Example: "10.127.134.1" # Default Gateway IP Address
                  DNSServers  = @()
                  vSwitchName = "<<Replace>>"                             #Example: "SDNSwitch"    # "<<Switch for internet connection>>"
                  VLANID      = "<<Replace>>"                             #Example: 1001           # VLAN Tag

                  # Enterprise network details behind the Enterprise Gateway                  
                  EntNetwork = @{
                      SwitchName     = "SiteA"
                      IPAddressSpace = "14.1.10.0"
                      IPAddress      = "14.1.10.1"
                      Mask           = 24
                  }
                  
                  # Enterprise Gateway's IPSec S2S VPN connection details
                  # Make sure you refer to the configuration in SDNExpressTenantGW for correct information
                  VpnConnection = @{
                      TunnelName   = "ToCloud"
                      TunnelType   = "IPSec"
                      Destination  = "<<Replace>>"                        #Example: "10.127.134.140"  # This must be the GatewayPublicIPAddress as specified in FabricConfig.psd1
                      SharedSecret = "111_aaa"

                      # This can be all of the HNV Subnets (& route Metric) for static routing; or Cloud Gateway's BGP IP Address (/32) (& route Metric)
                      IPv4Subnets  = @("<<Replace>>")                     #Example: "192.168.0.2/32:10"
                  }

                  # Enterprise Gateway's BGP Router and Cloud Peering details
                  BgpConfig = @{
                      LocalASN = "<<Replace>>"                            #Example: "64521"
                      PeerIP   = "<<Replace>>"                            #Example: "192.168.0.2"     # Cloud BGP Router's BGP IP Address
                      PeerASN  = "<<Replace>>"                            #Example: "64510"           # Cloud BGP Router's ASN
                  }

                  # Computer is an enterprise Gateway
                  Role = "Gateway"
                },
                @{ 
                  # Computer Name to be assigned to the Enterprise VM behind the IPSec S2S VPN Gateway
                  VMName = "IPSecVM01"
                  VMMemory=4GB                                          #Example: 4GB
                  
                  # Enterprise client VM's Internal IP Address and network details
                  IPAddress   = "14.1.10.10"
                  Mask        = 24
                  Gateway     = "14.1.10.1"
                  vSwitchName = "SiteA"             
                   
                  # Computer is an enterprise client VM
                  Role = "Client"
                }
            )
        },
        @{
            NodeName="<<Replace>>"                                        #Example: "Host-05"
            Role="HyperVHost"
            VMs=@(
                @{ 
                  # Computer Name to be assigned to the Enterprise GW used for GRE S2S VPN
                  VMName = "GreGW01"
                  VMMemory=4GB                                         #Example: 4GB
                  PortProfileID = "00000000-0000-0000-0000-000000000000"
                  
                  # Enterprise Gateway's Internet /DMZ IP Address and network details
                  IPAddress   = "<<Replace>>"                             #Example: "10.127.134.122"
                  Mask        = "<<Replace>>"                             #Example: 25
                  Gateway     = "<<Replace>>"                             #Example: "10.127.134.1"
                  DNSServers  = @()
                  vSwitchName = "<<Replace>>"                             #Example: "SDNSwitch"
                  VLANID      = "<<Replace>>"                             #Example: 1001
                  
                  # Enterprise network details behind the Enterprise Gateway                  
                  EntNetwork = @{
                      SwitchName     = "SiteB"
                      IPAddressSpace = "14.1.20.0"
                      IPAddress      = "14.1.20.1"
                      Mask           = 24
                  }
                  
                  # Enterprise Gateway's GRE S2S VPN connection details
                  VpnConnection = @{
                      TunnelName  = "ToCloud"
                      TunnelType  = "Gre"

                      # Must be the IP Address acquired by the "External" Network Adapter of the Cloud Gateway where GRE Tunnel has been provisioned
                      Destination = "<<Replace>>"                             #Example: "10.127.134.195"             
                      GreKey      = "1234"                                    # A unique GRE Key differentiating the tunnel

                      # Can be all of the HNV Subnets (& route Metric) for static routing; or Cloud Gateway's BGP IP Address (/32) (& route Metric)
                      IPv4Subnets = @("<<Replace>>")                          #Example: @("192.168.0.2/32:10")   
                  }
                  
                  # Enterprise Gateway's BGP Router and Cloud Peering details
                  BgpConfig = @{
                      LocalASN = "<<Replace>>"                            #Example: "64522"
                      PeerIP   = "<<Replace>>"                            #Example: "192.168.0.2"     # Cloud BGP Router's BGP IP Address
                      PeerASN  = "<<Replace>>"                            #Example: "64510"           # Cloud BGP Router's ASN
                  }
                  
                  # Computer is an enterprise Gateway
                  Role = "Gateway"
                }
            )
        },
        @{
            NodeName="<<Replace>>"                                        #Example: "Host-06"
            Role="HyperVHost"
            VMs=@(                
                @{ 
                  # Computer Name to be assigned to the Enterprise GW used for L3 Forwarding
                  VMName = "L3GW01"
                  VMMemory=4GB                                         #Example: 4GB
                  PortProfileID = "00000000-0000-0000-0000-000000000000"
                  
                  # Enterprise Gateway's DMZ IP Address and network details
                  IPAddress   = "<<Replace>>"                             #Example: "10.127.134.65"
                  Mask        = "<<Replace>>"                             #Example: 25
                  Gateway     = "<<Replace>>"                             #Example: "10.127.134.1"
                  DNSServers  = @()
                  vSwitchName = "<<Replace>>"                             #Example: "SDNSwitch"
                  VLANID      = "<<Replace>>"                             #Example: 1001

                  
                  # Enterprise Gateway's L3 Forwarding connectiondetails
                  VpnConnection = @{
                      TunnelType  = "L3"

                      # Must be same as the IP Address specified in L3 Tunnel's configuration (see SDNExpressTunnel)
                      Destination = "<<Replace>>"                         #Example: "10.127.134.55"           

                      # Can be all of the HNV Subnets for static routing; or Cloud Gateway's BGP IP Address (/32)
                      IPv4Subnets = @("<<Replace>>")                      #Example: @("192.168.0.2/32")       
                  }

                  # Enterprise network details behind the Enterprise Gateway                  
                  EntNetwork = @{
                      SwitchName     = "SiteC"
                      IPAddressSpace = "14.1.30.0"
                      IPAddress      = "14.1.30.1"
                      Mask           = 24
                  }
                  
                  # Enterprise Gateway's BGP Router and Cloud Peering details
                  BgpConfig = @{
                      LocalASN = "<<Replace>>"                            #Example: "64523"
                      PeerIP   = "<<Replace>>"                            #Example: "192.168.0.2"     # Cloud BGP Router's BGP IP Address
                      PeerASN  = "<<Replace>>"                            #Example: "64510"           # Cloud BGP Router's ASN
                  }

                  # Computer is an enterprise Gateway
                  Role = "Gateway"
                }
            )
         }
     )
}

