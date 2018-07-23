param(
   [string][parameter(Mandatory=$true)]$NCRestFQDNorIP,
   [string[]][parameter(Mandatory=$true)]$NetworkControllerNodes,
   [string][parameter(Mandatory=$true)]$OutputDirectory,
   [string[]][parameter(Mandatory=$false)]$HyperVHostNodes,
   [string][parameter(Mandatory=$true)]$Username,
   [string][parameter(Mandatory=$true)]$Password
)

$DIAGNOSTIC_LOGS_LOCATION = "C:\SDNDiagnostics\Logs\"

#### Network Controller State

function DumpConfigurationState()
{
   param (
      [parameter(Mandatory=$true)][string] $nc,
      [string][parameter(Mandatory=$true)]$OutputDirectory      
   )

   $outputfile = $OutputDirectory + "\\" + $nc.split(".")[0] + "_configurationstate.txt"
   if ($Global:AuthType -eq "X509")
   {
      Debug-NetworkControllerConfigurationState -NcIpAddress $nc | Out-File $outputfile
   } 
   elseif ($Global:AuthType -eq "Kerberos")
   {
      # Requires this to special file to be downloaded onto this host from GitHub
      # https://github.com/Microsoft/SDN/tree/master/Diagnostics/https://github.com/Microsoft/SDN/blob/master/Diagnostics/Debug-NetworkControllerConfigurationVMM.ps1
      Debug-NetworkControllerConfigurationStateVmm -NcIpAddress $nc | Out-File $outputfile
   }
}


function TriggerImosDump
{
   param (
      [parameter(Mandatory=$true)][string]$nc         # NC REST FQDN or IP with creds      
   )

   $uri = "https://" + $nc
   $properties = New-Object Microsoft.Windows.NetworkController.NetworkControllerStateProperties
   Invoke-NetworkControllerState -ConnectionUri $uri -Properties $properties –Force

   # Data will be collected along with other logs...
}


# Must be run on NC Node
function TriggerServiceFabricStatus
{
   # TODO: Need a way to get service fabric status that isn't interactive
}


# Collect output from Network Controller Nodes Logs and State
function CollectNCLogs
{
   param (
      [parameter(Mandatory=$true)][string[]]$ncnodes,
      [parameter(Mandatory=$false)][string]$TypeOfLogging = "Local"
   )

   if ($TypeOfLogging -eq "Local")
   {
      # These files should all be on the NC node from which they were run, by convention, this is $ncnodes[0]
      $ncnode = $ncnodes[0]
      robocopy /NP /NFL /NJS /NJH /NDL /E /R:1 "\\$ncnode\C$\SDNDiagnostics\NetworkControllerState", $OutputDirectory, "*SlbConfigState.txt"      
      rm "\\$ncnode\C$\SDNDiagnostics\NetworkControllerState\*SlbConfigState.txt"
      robocopy /NP /NFL /NJS /NJH /NDL /E /R:1 "\\$ncnode\C$\SDNDiagnostics\NetworkControllerState", $OutputDirectory, "*servicemodulereplicas.txt"
      rm "\\$ncnode\C$\SDNDiagnostics\NetworkControllerState\*servicemodulereplicas.txt"

      foreach ($node in $ncnodes) 
      {
         robocopy /NP /NFL /NJS /NJH /NDL /E /R:1 "\\$node\C$\SDNDiagnostics\NetworkControllerState", $OutputDirectory, "*xml"
         rm "\\$node\C$\SDNDiagnostics\NetworkControllerState\*xml"
      }
   }
}

#### Hyper-V Host State

function CollectHostLogs
{
   param (
      [parameter(Mandatory=$true)][string[]]$hostnodes      
   )

   foreach ($node in $hostnodes) 
   {
      robocopy /NP /NFL /NJS /NJH /NDL /E /R:1 "\\$node\C$\SDNDiagnostics\Logs", $OutputDirectory, "*PA.txt"
      rm "\\$node\C$\SDNDiagnostics\Logs\*PA.txt"
      robocopy /NP /NFL /NJS /NJH /NDL /E /R:1 "\\$node\C$\SDNDiagnostics\Logs", $OutputDirectory, "*ovsdb_ms_vtep.txt"
      rm "\\$node\C$\SDNDiagnostics\Logs\*ovsdb_ms_vtep.txt"
      robocopy /NP /NFL /NJS /NJH /NDL /E /R:1 "\\$node\C$\SDNDiagnostics\Logs", $OutputDirectory, "*_ipconfigall.txt"
      rm "\\$node\C$\SDNDiagnostics\Logs\*_ipconfigall.txt"
      robocopy /NP /NFL /NJS /NJH /NDL /E /R:1 "\\$node\C$\SDNDiagnostics\Logs", $OutputDirectory, "*_hostnetworking.txt"
      rm "\\$node\C$\SDNDiagnostics\Logs\*_hostnetworking.txt"
   }
}

#### MAIN ####

try {

   # Create creds (assume creds are same for NC Nodes and Hyper-V Hosts)
   $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force -Verbose
   $credential = New-Object System.Management.Automation.PSCredential($Username, $securePassword)  -Verbose

   # Create Remote PowerShell session for first NC Node
   $ncnode = $NetworkControllerNodes[0]
   $NC_PSSession = New-PSSession -ComputerName $ncnode -Credential $credential -EnableNetworkAccess -Verbose

   # Determine if we're using X509 or Kerberos for authentication
   $auth = Invoke-Command -Session $NC_PSSession -ScriptBlock { 
      $auth = (Get-NetworkControllerCluster).ClusterAuthentication
      $auth 
   }   
   $Global:AuthType = $auth.Value

   # Check to see if a cert with this subject name is on the localhost
   $cert = Get-ChildItem cert:\localmachine\root | where { $_.Subject -eq "CN=$NCRestFQDNorIP" }
   if ($cert -eq $null)
   {
      Write-Output "ERROR: NC REST Certificate is not available on this host"
      Exit 
   }
   else
   {
      $Global:NCRest = $NCRestFQDNorIP
   }
      
   # Check to see if Output Directory exists
   If (-Not (Test-Path $OutputDirectory))
   {
      Write-Output "Output directory does not exist. Creating..."
      md $OutputDirectory
   }
      
   Write-Output "Getting Network Controller Configuration State by invoking REST surface from this host"
   DumpConfigurationState -nc $Global:NCRest -outputdirectory $OutputDirectory
   
   #Write-Output "Dumping IMOS state"
   #TriggerImosDump($Global:NCRest)
     
   #Write-Output "Dumping the SLB Configuration state"
   #Invoke-Command -Session $NC_PSSession -ScriptBlock { Debug-SlbConfigState }

   Write-Output "Getting the Network Controller Service Modules' Replica Status..."
   $ncreplica_outputfile = "C:\\SDNDiagnostics\\NetworkControllerState\\" + $($Global:NCRest).split(".")[0] + "_servicemodulereplicas.txt"   
   Invoke-Command -Session $NC_PSSession -ArgumentList $ncreplica_outputfile -ScriptBlock { 
      param(
         [string][parameter(Mandatory=$true)]$ncreplica_outputfile
      )
      Get-NetworkControllerReplica |Out-File $ncreplica_outputfile 
   }

   Remove-PSSession $NC_PSSession 

   # Collect data from Network Controller
   CollectNCLogs($NetworkControllerNodes)
   
   # Grab Data from each host
   foreach ($node in $HyperVHostNodes)
   {      
      Write-Output "Grabbing data on $node"

      $Host_PSSession = New-PSSession -ComputerName $node -Credential $credential -EnableNetworkAccess -Verbose      
      Invoke-Command -Session $Host_PSSession -ArgumentList $OutputDirectory, $node -ScriptBlock { 
         param 
         (
            [string][parameter(Mandatory=$true)]$OutputDirectory,
            [string][parameter(Mandatory=$true)]$node,
            [bool][parameter(Mandatory=$false)]$IncludeTraces = $true
         )
    
         $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"            
         $DIAGNOSTIC_LOGS_LOCATION = "C:\SDNDiagnostics\Logs\"

         $service=Get-Service NCHostAgent
         if ($service.Status -ne "Stopped") 
         { 
            $msvtep_outfile = $DIAGNOSTIC_LOGS_LOCATION + $node + "_ovsdb_ms_vtep.txt"
            Write-Output "Dump MS_VTEP"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep > "$msvtep_outfile"
            
            $msfirewall_outfile = $DIAGNOSTIC_LOGS_LOCATION + $node + "_ovsdb_ms_firewall.txt" 
            Write-Output "Dump MS_FIREWALL"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall > $msfirewall_outfile 
            
            #ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion > "$OutputDirectory\ovsdb_ms_service_insertion.txt"
         }
        
         $pa_outfile = $DIAGNOSTIC_LOGS_LOCATION + $node + "_PA.txt"
         Write-Output "Getting Provider Addresses"
         Get-ProviderAddress | Out-File $pa_outfile 

         $ipconfig_outfile = $DIAGNOSTIC_LOGS_LOCATION + $node + "_ipconfigall.txt"
         Write-Output "Getting ipconfigs"
         ipconfig /allcompartments /all > $ipconfig_outfile 
         
         $hostnetwork_outfile = $DIAGNOSTIC_LOGS_LOCATION + $node + "_hostnetworking.txt"
         Write-Output "Getting SDN VMSwitch"
         $vmswitch = Get-VMSwitch | where { ($_ |Get-VMSwitchExtension -Name "Windows Azure VFP Switch Extension").Enabled }                 
         $vmswitch |fl |Out-File $hostnetwork_outfile

         $pnics = $vmswitch.NetAdapterInterfaceDescriptions
         foreach ($pnic in $pnics)
         {
            Write-Output "Getting Net Adapter info for $pnic"
            Get-NetAdapter -InterfaceDescription $pnic |fl >> $hostnetwork_outfile        
         }

         Write-Output "Getting VM NICs"
         $vmnics = Get-VMNetworkAdapter * |where { $_.SwitchName -eq "$($vmswitch.Name)" }
         $vmnics >> $hostnetwork_outfile         
         foreach ($vmNic in $vmNics) 
         {
             write-output ("Getting port profile for VM NIC $($vmNic.Name) on VM $($vmNic.VMName)")
             $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $vmNic
             if ( $currentProfile -eq $null) 
             {
                 write-output "WARNING: $vmNic.Name does not have a port profile" |Out-File $hostnetwork_outfile -Append
             } else 
             {
                 write-output ("$($vmNic.VMName) Port Profile Id:   $($currentProfile.SettingData.ProfileId)") |out-file $hostnetwork_outfile -Append
                 write-output ("$($vmNic.VMName) Port Profile Data: $($currentProfile.SettingData.ProfileData)") |out-file $hostnetwork_outfile -Append
             }
             Write-output ("Getting isolation settings for VM NIC $($vmNic.Name) on VM $($vmNic.VMName)")
             Get-VMNetworkAdapterVlan $vmnic |out-file $hostnetwork_outfile -Append
             Get-VMNetworkAdapterIsolation $vmnic |out-file $hostnetwork_outfile -Append

             # TODO: Get vfp port state, layers, and rules
          }                                       
       }
       Remove-PSSession $Host_PSSession    
   }
   CollectHostLogs($HyperVHostNodes)

} catch  
{
   Write-Output $_.Exception.Message
   Write-Output $_.Exception.ItemName
}
