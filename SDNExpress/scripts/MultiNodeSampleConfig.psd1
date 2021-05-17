@{
    ScriptVersion      = "2.0"

     VHDPath           = "\\fileserver\share\Media"
     VHDFile           = "WindowsServer2016Datacenter.vhdx"

     VMLocation        = "c:\VMs"
     JoinDomain        = "contoso.com"

     SDNMacPoolStart     = "00-11-22-00-01-00"
     SDNMacPoolEnd       = "00-11-22-00-01-FF"

     ManagementSubnet  = "10.127.132.128/25"
     ManagementGateway = "10.127.132.129"
     ManagementDNS     = @("10.127.130.7", "10.127.130.8")
     ManagementVLANID  = 7

    DomainJoinUsername  = "Contoso\greg"

     LocalAdminDomainUser = "Contoso\greg"

     RestName = "sdn.contoso.com"

     NCs = @(
                    @{ComputerName='Contoso-NC01'; HostName='Host1'; ManagementIP='10.127.132.169'; MACAddress='001DD8220000'},
                    @{ComputerName='Contoso-NC02'; HostName='Host2'; ManagementIP='10.127.132.170'; MACAddress='001DD8220001'}
                    @{ComputerName='Contoso-NC03'; HostName='Host3'; ManagementIP='10.127.132.171'; MACAddress='001DD8220002'}
    )
     Muxes = @(
                    @{ComputerName='Contoso-Mux01'; HostName='Host1'; ManagementIP='10.127.132.172'; MACAddress='001DD8220003'; PAIPAddress='10.10.182.4'; PAMACAddress='001DD8220004'},
                    @{ComputerName='Contoso-Mux02'; HostName='Host2'; ManagementIP='10.127.132.173'; MACAddress='001DD8220005'; PAIPAddress='10.10.182.5'; PAMACAddress='001DD8220006'}
    )
     Gateways = @(
                    @{ComputerName='Contoso-GW01'; HostName='Host1'; ManagementIP='10.127.132.174'; MACAddress='001DD8220007'; FrontEndIp='10.10.182.6'; FrontEndMac="001DD8220008"; BackEndMac="001DD8220009"},
                    @{ComputerName='Contoso-GW02'; HostName='Host2'; ManagementIP='10.127.132.175'; MACAddress='001DD822000A'; FrontEndIp='10.10.182.7'; FrontEndMac="001DD822000B"; BackEndMac="001DD822000C"}
    )

     HyperVHosts = @(
                    "Host1", 
                    "Host2", 
                    "Host3"
    )

    NCUsername   = "Contoso\greg"

    PASubnet         = "10.10.182.0/25"
    PAVLANID         = '11'
    PAGateway        = '10.10.182.1'
    PAPoolStart      = '10.10.182.6'
    PAPoolEnd        = '10.10.182.13'  

    SDNASN =           "64628"
    Routers = @(
                    @{ RouterASN='64623'; RouterIPAddress='10.10.182.1'}
    )

    PrivateVIPSubnet = "10.10.183.0/29"
    PublicVIPSubnet  = "10.127.132.0/29"

    PoolName         = "DefaultAll"
    GRESubnet        = "192.168.0.0/24"
    Capacity         = 10000


    # Optional fields.  Uncomment items if you need to override the defaults.

    # Specify ProductKey if you have a product key to use for newly created VMs.  If this is not specified you may need 
    # to connect to the VM console to proceed with eval mode.
    # ProductKey       = '#####-#####-#####-#####-#####'

    # Switch name is only required if more than one virtual switch exists on the Hyper-V hosts.
    # SwitchName=''

    # Amount of Memory and number of Processors to assign to VMs that are created.
    # If not specified a default of 8 procs and 8GB RAM are used.
    # VMMemory = 4GB
    # VMProcessorCount = 4

    # If Locale and Timezone are not specified the local time zone of the deployment machine is used.
    # Locale           = ''
    # TimeZone         = ''

    # Passwords can be optionally included if stored encrypted as text encoded secure strings.  Passwords will only be used
    # if SDN Express is run on the same machine where they were encrypted, otherwise it will prompt for passwords.
    # DomainJoinSecurePassword  = ''
    # LocalAdminSecurePassword   = ''
    # NCSecurePassword   = ''

}
