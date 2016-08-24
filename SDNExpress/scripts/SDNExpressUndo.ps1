# --------------------------------------------------------------
#  Copyright © Microsoft Corporation.  All Rights Reserved.
#  Microsoft Corporation (or based on where you live, one of its affiliates) licenses this sample code for your internal testing purposes only.
#  Microsoft provides the following sample code AS IS without warranty of any kind. The sample code arenot supported under any Microsoft standard support program or services.
#  Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#  The entire risk arising out of the use or performance of the sample code remains with you.
#  In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the code be liable for any damages whatsoever
#  (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
#  arising out of the use of or inability to use the sample code, even if Microsoft has been advised of the possibility of such damages.
# ---------------------------------------------------------------
<#
.SYNOPSIS 
    Removes the virtual machines and configuration created by the 
    SDNExpress.ps1 script
.EXAMPLE
    .\SDNExpressUndo -ConfigurationDataFile .\MyConfig.psd1
    Reads in the configuration from a PSD1 file that contains a hash table 
    of settings data and removes any settings applied.
.EXAMPLE
    .\SDNExpressUndo -ConfigurationData $MyConfigurationData
    Uses the hash table that is passed in as the configuration data.  This 
    parameter set is useful when programatically generating the 
    configuration data. This configuration data must match what was passed
    in to .\SDNExpress
.NOTES

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationFile")]
    [String] $ConfigurationDataFile=$null,
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationData")]
    [object] $ConfigurationData=$null
)    

$global:stopwatch = [Diagnostics.Stopwatch]::StartNew()

switch ($psCmdlet.ParameterSetName) 
{
    "ConfigurationFile" {
        Write-Verbose "Using configuration from file [$ConfigurationDataFile]"
        $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
    }
    "ConfigurationData" {
        Write-Verbose "Using configuration passed in from parameter"
        $configdata = $configurationData 
    }
}
              
Configuration UnConfigureHost
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.Where{$_.Role -eq "HyperVHost" }.NodeName
    {
        script "RemoveVFP"
        {
            SetScript = {
                $vswitch = get-vmswitch
                Disable-VmSwitchExtension -VMSwitchName $vswitch.name -Name "Microsoft Azure VFP Switch Extension"
            }
            TestScript = {
                $vswitch = get-vmswitch
                $ext = Get-VmSwitchExtension -VMSwitchName $vswitch.name -Name "Microsoft Azure VFP Switch Extension"
                return $ext.Enabled -eq $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        script "RemoveMyCert"
        {
            SetScript = {
                 get-childitem Cert:\LocalMachine\my | where {$_.subject.ToUpper().StartsWith("CN=$($using:node.nodename).$($using:node.FQDN)".ToUpper())} | remove-item -force
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        script "RemoveRootCert"
        {
            SetScript = {
                  $nc = "$($using:node.NetworkControllerRestname)"
                  (get-childitem Cert:\localmachine\root | where {$_.subject.ToUpper().StartsWith("CN=$nc".ToUpper())}) | remove-item -force
                  write-verbose "Remove certs: $nc"
            }
            TestScript = {
                return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }

        script "StopSLBHostAgent"
        {
            SetScript = {
                  stop-service SLBHostAgent -Force
            }
            TestScript = {
                  return (get-service SLBHostAgent).Status -eq "Stopped"
            }
            GetScript = {
                return @{ result = $true }
            }
        }   

        script "StopNCHostAgent"
        {
            SetScript = {
                  stop-service NCHostAgent -Force
            }
            TestScript = {
                  return (get-service NCHostAgent).Status -eq "Stopped"
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        script "CleanupPAHostVNIC"
        {
            SetScript = {
                try { Remove-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName PAhostVNic } catch { }
                try { Set-VmNetworkAdapterIsolation -ManagementOS -IsolationMode None -VMNetworkAdapterName PAhostVNic } catch { }
                try { remove-vmnetworkadapter -Name pahostvnic -ManagementOS } catch { }
            }
            TestScript = {
                $paNics = (get-vmnetworkadapter -managementos | where {$_.Name -eq "PAHostvnic" })
                return ($paNics.Count -eq 0)
            }
            GetScript = {
                return @{ result = $true }
            }
        }     


        script "CleanupDRHostVNIC"
        {
            SetScript = {
                try { Remove-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName DRhostVNic } catch { }
                try { Set-VmNetworkAdapterIsolation -ManagementOS -IsolationMode None -VMNetworkAdapterName DRhostVNic } catch { }
                try { remove-vmnetworkadapter -Name drhostvnic -ManagementOS } catch { }
            }
            TestScript = {
                $drNics = (get-vmnetworkadapter -managementos | where {$_.Name -eq "DRHostvnic" })
                return ($drNics.Count -eq 0)
            }
            GetScript = {
                return @{ result = $true }
            }
        }  
        
        script "CleanupTracing"
        {
            SetScript = {
                   del c:\windows\tracing\*.* -recurse 
                   }
            TestScript = {
                  return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }     
        
        script "RestoreOVSDBConfFiles"
        {
            SetScript = {
                   copy-item -Path "$($using:node.InstallSrcDir)\agentconf\*.conf" -Destination "c:\programdata\microsoft\windows\nchostagent"
            }
            TestScript = {
                  return $false
            }
            GetScript = {
                return @{ result = $true }
            }
        }   
        
        foreach ($VMInfo in $node.VMs) {

            script "RemoveVM-$($VMInfo.VMName)"
            {
                SetScript = {
                    write-verbose "Getting VM"
                    $vm = get-vm | where {$_.Name -eq $($using:VMInfo.VMName)}
                    if ($vm -ne $null) {
                        write-verbose "Stopping VM"
                        $vm | stop-vm -force -TurnOff
                        sleep 1
                        write-verbose "Removing VM"
                        $vm | remove-vm -force
                        sleep 1
                    }
            
                }
                TestScript = {
                      return (get-vm | where {$_.Name -eq $($using:VMInfo.VMName)}) -eq $null
                }
                GetScript = {
                    return @{ result = $true }                
                }
            }  

            script "DismountImage-$($VMInfo.VMName)"
            {
                SetScript = {
                    $mountpath = $using:node.MountDir+$($using:VMInfo.VMName)

                    Write-verbose "Dis-Mounting image [$mountpath]"
                    DisMount-WindowsImage -Save -path $mountpath
                }
                TestScript = {
                    return ((Test-Path "$($using:node.MountDir)$($using:vminfo.vmname)\Windows") -ne $True)
                }
                GetScript = {
                    return @{ result = DisMount-WindowsImage -Save -path ($using:node.MountDir+$using:vminfo.vmname) }
                }
            } 

            script "DeleteVMDir-$($VMInfo.VMName)"
            {
                SetScript = {

                    write-verbose "Removing VM directory"
                    rm -recurse -force ("$($Using:node.VMLocation)\$($Using:VMInfo.VMName)")
                }
                TestScript = {
                       $exist = (Test-Path ("$($Using:node.VMLocation)\$($Using:VMInfo.VMName)")) -eq $False

                    return $exist
                }
                GetScript = {
                    return @{ result = $true }
                }
            } 

            script "DeleteMountPoint-$($VMInfo.VMName)"
            {
                SetScript = {
                    write-verbose "Removing VM mount directory"
                    rm -recurse -force ("c:\Temp$($Using:VMInfo.VMName)")
                }
                TestScript = {
                    return ((Test-Path "c:\Temp$($Using:VMInfo.VMName)") -ne $True)
                }
                GetScript = {
                    return @{ result = $true }
                }
            }
        }
        
        script "RemoveCertsDirectory"
        {
            SetScript = {
                $directory = ("$($env:systemdrive)\$($Using:node.CertFolder)")
                write-verbose "Removing contents of Certs directory: $directory"

                rm -recurse -force "$directory\*"
            }
            TestScript = {
                return ((Test-Path "$($env:systemdrive)\$($Using:node.CertFolder)") -ne $True)
            }
            GetScript = {
                return @{ result = $true }
            }
        }
        
        script "RemoveToolsDirectory"
        {
            SetScript = {
                $directory = ("$($Using:node.ToolsLocation)")
                write-verbose "Removing contents of Tools directory: $directory"

                rm -recurse -force "$directory\*"
            }
            TestScript = {
                return ((Test-Path "$($Using:node.ToolsLocation)") -ne $True)
            }
            GetScript = {
                return @{ result = $true }
            }
        }
    }
}

Function CleanupDeploymentHost
{
    Write-Verbose "Cleaning up the deployment machine"

    Remove-Item .\UnConfigureHost -Force -Recurse 2>$null

    $certFolder = "$($configData.AllNodes[0].installsrcdir)\$($configData.AllNodes[0].certfolder)"
    if (Test-Path "$certFolder")
    {
        Write-Verbose "Deleting certs from $certFolder"
        rm -recurse -force "$certFolder\*"
    }
}


Remove-Item .\UnConfigureHost -Force -Recurse 2>$null

UnConfigureHost -ConfigurationData $ConfigData -verbose 
Start-DscConfiguration -Path .\UnConfigureHost -Wait -Force -Verbose -erroraction continue

CleanupDeploymentHost
