powreshell -c {
    Configuration DbTier
    {
        Node ("localhost")
        {
            WindowsFeature IIS
            {
                Ensure = "Present"
                Name = "Web-Server"
            }

            script EnableRDP
            {
                SetScript = {
                    $RDP = Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices -Authentication 6 -ErrorAction Stop
                    $RDP.SetAllowTsConnections(1,1)
                }
                TestScript = {
                    return $false
                }
                GetScript = {
                    return @{ result = "" }
                }
            }
            script EnablePing
            {
                SetScript = {
                    New-NetFirewallRule -Name Allow_Ping -DisplayName "Allow Ping" -Description "Packet Internet Groper ICMPv4" -Protocol ICMPv4 -IcmpType 8 -Enabled True -Profile Any -Action Allow
                }
                TestScript = {
                    return $false
                }
                GetScript = {
                    return @{ result = "" }
                }
            }
        }
    }

    WebTier
    Start-DscConfiguration -Path .\DbTier -Computername localhost -Wait -force -verbose
}