param(
   [string][parameter(Mandatory=$true)]$NCRestFQDN,
   [string[]][parameter(Mandatory=$true)]$NetworkControllerNodes,
   [string][parameter(Mandatory=$true)]$OutputDirectory,
   [string[]][parameter(Mandatory=$false)]$HyperVHostNodes,
   [string][parameter(Mandatory=$true)]$Username,
   [string][parameter(Mandatory=$true)]$Password
)


#### Network Controller State

function DumpConfigurationState()
{
   param (
      [parameter(Mandatory=$true)][string] $nc,
      [string][parameter(Mandatory=$true)]$OutputDirectory      
   )

   $outputfile = $OutputDirectory + "\\" + $nc.split(".")[0] + "_configurationstate.txt"
   Debug-NetworkControllerConfigurationState -NcIpAddress $nc | Out-File $outputfile
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
      robocopy /E /R:1 "\\$ncnode\C$\SDNDiagnostics\NetworkControllerState", $OutputDirectory, "*SlbConfigState.txt"      
      robocopy /E /R:1 "\\$ncnode\C$\SDNDiagnostics\NetworkControllerState", $OutputDirectory, "*servicemodulereplicas.txt"      

      foreach ($node in $ncnodes) 
      {
         robocopy /E /R:1 "\\$node\C$\SDNDiagnostics\NetworkControllerState", $OutputDirectory, "*xml"
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
      robocopy /E /R:1 "\\$node\C$\SDNDiagnostics\Logs", $OutputDirectory, "*PA.txt"
      robocopy /E /R:1 "\\$node\C$\SDNDiagnostics\Logs", $OutputDirectory, "*ovsdb_ms_vtep.txt"
   }
}

#### MAIN ####

try {

   $NCRestIP = ""

   # TODO: Would be awesome to have dynamically loaded "diagnostic modules" to collect additional info - specified at run-time or statically in script

   # TODO: Determine if we're using X.509 certs or Kerberos for authentication (check cert store my or root)
   $Global:authtype = "X509"
   
   $Global:NCRest = ""
   if ($Global:authtype -eq "X509")
   {
      $Global:NCRest = $NCRestFQDN
   }
   
   # TODO: Check to see if Output Directory exists

   # Create creds (assume creds are same for NC Nodes and Hyper-V Hosts)
   $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force -Verbose
   $credential = New-Object System.Management.Automation.PSCredential($Username, $securePassword)  -Verbose
   
   Write-Output "Getting Network Controller state (Configuration and IMOS) by invoking REST surface from this host..."
   DumpConfigurationState -nc $Global:NCRest -outputdirectory $OutputDirectory
   TriggerImosDump($Global:NCRest)

   # Create Remote PowerShell session for first NC Node
   $ncnode = $NetworkControllerNodes[0]
   $NC_PSSession = New-PSSession -ComputerName $ncnode -Credential $credential -EnableNetworkAccess -Verbose
   
   Write-Output "Getting the SLB Configuration state..."
   Invoke-Command -Session $NC_PSSession -ScriptBlock { Debug-SlbConfigState }

   Write-Output "Getting the Network Controller Service Modules' Replica Status..."
   $ncreplica_outputfile = "C:\\SDNDiagnostics\\NetworkControllerState\\" + $($Global:NCRest).split(".")[0] + "_servicemodulereplicas.txt"
   Write-Output $ncreplica_outputfile
   Invoke-Command -Session $NC_PSSession -ArgumentList $ncreplica_outputfile -ScriptBlock { 
      param(
         [string][parameter(Mandatory=$true)]$ncreplica_outputfile
      )
      Get-NetworkControllerReplica |Out-File $ncreplica_outputfile 
   }

   # Collect data from Network Controller
   CollectNCLogs($NetworkControllerNodes)
   
   # Grab Data from each host
   foreach ($node in $HyperVHostNodes)
   {
      Write-Output "Grabbingdata on $node"
      $Host_PSSession = New-PSSession -ComputerName $node -Credential $credential -EnableNetworkAccess -Verbose      
      Invoke-Command -Session $Host_PSSession -ArgumentList $OutputDirectory, $node -ScriptBlock { 
         param 
         (
            [string][parameter(Mandatory=$true)]$OutputDirectory,
            [string][parameter(Mandatory=$true)]$node,
            [bool][parameter(Mandatory=$false)]$IncludeTraces = $true
         )
                
         $service=Get-Service NCHostAgent
         if ($service.Status -ne "Stopped") 
         { 
            $msvtep_outfile = "C:\SDNDiagnostics\Logs\" + $node + "_ovsdb_ms_vtep.txt"
            Write-Output "Dump MS_VTEP"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep > "$msvtep_outfile"
            #ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall"$OutputDirectory\ovsdb_ms_firewall.txt" 
            #ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion > "$OutputDirectory\ovsdb_ms_service_insertion.txt"
         }
        
         $pa_outfile = "C:\SDNDiagnostics\Logs\" + $node + "_PA.txt"
         Get-ProviderAddress | Out-File $pa_outfile 
         #ipconfig /allcompartments /all > "$OutputDirectory\" + $node + "_ipconfigall.txt"
         #C:\Tools\showAllPolicy.ps1 ExternalPrivate > "$OutputDirectory\policy.txt"
         #Get-NetAdapter > "$OutputDirectory\networkadapters.txt"
         #Get-NetAdapter | fl * >> "$OutputDirectory\networkadapters.txt"
         #Get-VMNetworkAdapter -All > "$OutputDirectory\vmnetworkadapters.txt"
         #get-netipaddress -IncludeAllCompartments > "$OutputDirectory\netipaddress.txt"
         #get-netroute -IncludeAllCompartments > "$OutputDirectory\netroute.txt"
         #Get-VMNetworkAdapterVlan > "$OutputDirectory\vmnetworkadaptersvlan.txt"
         #get-vm | Get-VMNetworkAdapter | fl * >> "$OutputDirectory\vmnetworkadapters.txt"
         #Get-VMNetworkAdapterIsolation | fl * > "$OutputDirectory\vmnetworkadapterisolation.txt"
         #Get-VMSwitch  > "$OutputDirectory\vmswitches.txt"
         #Get-VMSwitch | fl * >> "$OutputDirectory\vmswitches.txt"
         #get-vm | Get-vmnetworkadapter | Foreach { C:\Tools\DumpVmPort.ps1 -VMName $_.VMName -VMNetworkAdapterName $_.Name  -OutFile "$OutputDirectory\vmports.txt" }
         #Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS > "$OutputDirectory\VMNetworkAdapterRoutingDomainMapping.txt"
         #Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS | fl * >> "$OutputDirectory\VMNetworkAdapterRoutingDomainMapping.txt"
         #vfpctrl /list-queue /switch ExternalPrivate >> "$OutputDirectory\vfpctrl-list-queue.txt"
         #vfpctrl /get-qos-config /switch ExternalPrivate >> "$OutputDirectory\vfpctrl-get-qos-config.txt"
         
    }

    CollectHostLogs($HyperVHostNodes)

   }

} catch  
{
   Write-Output $_.Exception.Message
   Write-Output $_.Exception.ItemName
}
