SDNSecurityToolkit is a module for adding useful SDN security tools to powershell. Currently it just
houses Invoke-SDNVipScan.

Invoke-SDNVipScan is a simple Cmdlet for monitoring the status of public VIPs in WS19 SDN deployments.

Setup:
This tool requires nmap to run which may be downloaded for free at https://nmap.org/download.html, at 
the bottom of the windows section. The specific version this tool was developed with is available for 
direct download at https://nmap.org/dist/nmap-7.80-win32.zip. To run this Nmap exe you will need to have 
Windows Visual C++ 2013 installed, which can be installed from the Nmap zip folder by running 
vcredist_x86.exe.

To use the tool do import-module SDNSecurityToolkit.psm1, which will let you run the Invoke-SdnVipScan 
cmdlet with the parameters specified below.

Parameters:
-sdnNetworkResourceFile: path to your network resource file used for SDN Express
-URI: your SDN connection URI if not specifying a network resource file.
-nmapPath: path to your Nmap executable.
-jsonoutput: path to save a json output of the tool's findings.
-htmloutput: path to save a simple html report of the tool's findings.
-deepscan: will enable the -Pn flag on logical network list scans, which will find open ports when
the host is not immediately reporting up. This is useful since many firewalls will filter basic probes
but is MUCH slower when scanning an IP range without a specifying a specific port.

Functionality:
The tool will first report on VIPs taken from frontendipconfigs found accross loadbalancers and 
find their associated rules, whether LB rules, or inbound or outbound NAT.

The tool will then scan the ports being used by LB rules on the public vips and report if nmap sees them
as filtered or open.

The tool will then do a scan accross your public logical network list for any open IP addresses that are
not associated with any LB rules. If it finds one it will raise an alert that there is an inconsistency
in your SDN deployment.

Finally the tool outputs json and html reports if requested.
