param(
   [string]$switchName = $(throw "please specify a switch name")
  )

$switches = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualEthernetSwitch
foreach ($switch in $switches) {
              if ( $switch.ElementName -eq $switchName) {
                             $ExternalSwitch = $switch
                             break
              }
}

$vfpCtrlExe = "vfpctrl.exe"
$ports = $ExternalSwitch.GetRelated("Msvm_EthernetSwitchPort", "Msvm_SystemDevice", $null, $null, $null, $null, $false, $null)
foreach ($port in $ports) {
	$portGuid = $port.Name
	echo "Policy for port : " $portGuid
	& $vfpCtrlExe /list-space  /port $portGuid
	& $vfpCtrlExe /list-mapping  /port $portGuid
	& $vfpCtrlExe /list-rule  /port $portGuid
	& $vfpCtrlExe /port $portGuid /get-port-state
	& $vfpCtrlExe /port $portGuid /list-nat-range
}
