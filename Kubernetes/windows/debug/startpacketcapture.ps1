#Requires -RunAsAdministrator

[CmdletBinding()]
param
(
    # Path with filename where the ETL file will be saved. Format: <path>\<filename>.etl
    [string]
    $EtlFile = "C:\server.etl",

    # How many bytes of the packet to collect. Default is 256 bytes to collect encapsulated headers.
    [int]
    $snapLen = 256,

    # Maximum file size in megabytes. 0 means that there is no maximum
    [int]
    $maxFileSize = 250,

    # Does not prompt/pause execution and wait on user input.
    [switch]
    $NoPrompt,

    # Does not collect network packets.
    [switch]
    $NoPackets,

    # Collects logs after user presses q to stop tracing. Ignored when -NoPrompt set.
    [switch]
    $CollectLogs
)

### CLASSES AND FUNCTIONS ###
#region


# Data structure for ETW providers.
# This implementation requires the use of the ETW GUID. 
# Everything else is optional with default values for level and keywords.
class Provider
{
    # [Optional w/ GUID] ETW name
    [string]$Name
    # [Optional w/ Name] ETW GUID - Recommended! ETW name doesn't always resolve properly, GUID always does.
    [guid]$GUID
    # [Optional] Logging level. Default = [byte]::MaxValue (0xff)
    [byte]$Level
    # [Optional] Logging keywords. Default = [UInt64]::MaxValue (0xffffffffffffffff)
    [uint64]$MatchAnyKeyword

    # supported methods of creating a provider object
    #region

    # all properties
    Provider(
        [string]$Name,
        [guid]$GUID,
        [byte]$Level,
        [uint64]$MatchAnyKeyword
    )
    {
        $this.Name              = $Name
        $this.GUID              = $GUID
        $this.Level             = $level
        $this.MatchAnyKeyword   = $MatchAnyKeyword
    }

    # all but the Name property
    Provider(
        [guid]$GUID,
        [byte]$Level,
        [uint64]$MatchAnyKeyword
    )
    {
        $this.Name              = ""
        $this.GUID              = $GUID
        $this.Level             = $level
        $this.MatchAnyKeyword   = $MatchAnyKeyword
    }

    # GUID and level property
    Provider(
        [guid]$GUID,
        [byte]$Level
    )
    {
        $this.Name              = ""
        $this.GUID              = $GUID
        $this.Level             = $level
        $this.MatchAnyKeyword   = [UInt64]::MaxValue
    }

    # GUID, name, and level property
    Provider(
        [string]$Name,
        [guid]$GUID,
        [byte]$Level
    )
    {
        $this.Name              = $Name
        $this.GUID              = $GUID
        $this.Level             = $level
        $this.MatchAnyKeyword   = [UInt64]::MaxValue
    }

    # only GUID
    Provider(
        [guid]$GUID
    )
    {
        $this.Name              = ""
        $this.GUID              = $GUID
        $this.Level             = [byte]::MaxValue
        $this.MatchAnyKeyword   = [UInt64]::MaxValue
    }

    #endregion Provider()
}


# Downloads a file from the Internet.
# Returns the full path to the download.
function Get-WebFile
{
    param ( 
        [string]$URI,
        [string]$savePath,
        [string]$fileName
    )

    Write-Debug "Get-WebFile - Start."
    # make sure we don't try to use an insecure SSL/TLS protocol when downloading files
    Write-Debug "Get-WebFile - Disabling unsupported SSL/TLS protocls."
    $secureProtocols = @() 
    $insecureProtocols = @( [System.Net.SecurityProtocolType]::SystemDefault, 
                            [System.Net.SecurityProtocolType]::Ssl3, 
                            [System.Net.SecurityProtocolType]::Tls, 
                            [System.Net.SecurityProtocolType]::Tls11) 
    foreach ($protocol in [System.Enum]::GetValues([System.Net.SecurityProtocolType])) 
    { 
        if ($insecureProtocols -notcontains $protocol) 
        { 
            $secureProtocols += $protocol 
        } 
    } 
    [System.Net.ServicePointManager]::SecurityProtocol = $secureProtocols

    Write-Verbose "Get-WebFile - Attempting download of $URI."
    try 
    {
        Invoke-WebRequest -Uri $URI -OutFile "$savePath\$fileName" -MaximumRedirection 5 -EA Stop
        Write-Verbose "Get-WebFile - File downloaded to $savePath\$fileName."
    } 
    catch 
    {
        # return terminating error
        return (Write-Error "Could not download $URI`: $_" -EA Stop)
    }

    #Add-Log "Downloaded successfully to: $output"
    Write-Debug "Get-WebFile - Returning: $savePath\$fileName "
    Write-Debug "Get-WebFile - End."
    return "$savePath\$fileName"
}

#endregion CLASSES and FUNCTIONS


### CONSTANTS and VARIABLES ###
#region

#
# list of ETW providers to be traced
#
# template: [Provider]::New('',6), # 
                         # Control plane
[Provider[]]$providers = [Provider]::New('{564368D6-577B-4af5-AD84-1C54464848E6}', 6), # Microsoft-Windows-Overlay-HNSPlugin
                         [Provider]::New('{0c885e0d-6eb6-476c-a048-2457eed3a5c1}', 6), # Microsoft-Windows-Host-Network-Service
                         [Provider]::New('{80CE50DE-D264-4581-950D-ABADEEE0D340}', 6), # Microsoft.Windows.HyperV.Compute
                         [Provider]::New('{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}', 6), # Microsoft.Windows.HostNetworkingService.PrivateCloudPlugin
                         [Provider]::New('{93f693dc-9163-4dee-af64-d855218af242}', 6), # Microsoft-Windows-Host-Network-Management
                         [Provider]::New('{6C28C7E5-331B-4437-9C69-5352A2F7F296}', 6), # Microsoft.Windows.Hyper.V.VmsIf
                         # Firewall
                         [Provider]::New('{5EEFEBDB-E90C-423a-8ABF-0241E7C5B87D}', 6), # Windows Firewall Service
                         [Provider]::New('{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}', 6), # Microsoft-Windows-Windows Firewall With Advanced Security
                         # Protocols
                         [Provider]::New('{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}', 6), # Microsoft-Windows-TCPIP
                         [Provider]::New('{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}', 6), # Microsoft-Windows-DNS-Client
                         [Provider]::New('{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}', 6), # Microsoft-Windows-Dhcp-Client
                         [Provider]::New('{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}', 6), # Microsoft-Windows-DHCPv6-Client
                         # NAT
                         [Provider]::New('{66C07ECD-6667-43FC-93F8-05CF07F446EC}', 6), # Microsoft-Windows-WinNat
                         [Provider]::New('{AA7387CF-3639-496A-B3BF-DC1E79A6fc5A}', 6), # WIN NAT WPP
                         [Provider]::New('{AE3F6C6D-BF2A-4291-9D07-59E661274EE3}', 6), # IP NAT WPP
                         # Shared Access
                         [Provider]::New('{9B322459-4AD9-4F81-8EEA-DC77CDD18CA6}', 6), # Shared Access Service WPP Provider
                         [Provider]::New('{A6F32731-9A38-4159-A220-3D9B7FC5FE5D}', 6), # Microsoft-Windows-SharedAccess_NAT
                         # VmSwitch Enable ETW and WPP Events - Control Path Only
                         [Provider]::New('{1F387CBC-6818-4530-9DB6-5F1058CD7E86}', 6), # vmswitch - 0xFFDFFFFB
                         [Provider]::New('{67DC0D66-3695-47c0-9642-33F76F7BD7AD}', 6),  # Microsoft-Windows-Hyper-V-VmSwitch - 0xFFFFFFDD
                         # available starting in build 19041. Safe to add here since the try-catch will silently fail if ETW not present
                         [Provider]::New('{94DEB9D1-0A52-449B-B368-41E4426B4F36}', 6),  # Microsoft.Windows.Hyper.V.NetSetupHelper
                         # VFPEXT is an optional component
                         [Provider]::New('{9F2660EA-CFE7-428F-9850-AECA612619B0}', 6) # Microsoft-Windows-Hyper-V-VfpExt - 0x00410000
                         
                         
# capture name
$sessionName = 'HnsPacketCapture'

#endregion CONSTANTS and VARIABLES


### MAIN ###

#
# Stop any existing session and create a new session
#
Write-Debug "Cleaning up any failed $sessionName sessions."
Stop-NetEventSession $sessionName -ErrorAction Ignore | Out-Null
Remove-NetEventSession $sessionName -ErrorAction Ignore | Out-Null

#
# create capture session
#
try
{
    Write-Verbose "Creating the $sessionName capture session."
    New-NetEventSession $sessionName -CaptureMode SaveToFile -MaxFileSize $maxFileSize -LocalFilePath $EtlFile -EA Stop | Out-Null
}
catch
{
    return (Write-Error "Failed to create the NetEventSession: $_" -EA Stop)
}

#
# add packet capture when -NoPackets not in use
#
if (-NOT $NoPackets.IsPresent)
{
    Write-Verbose "Adding packet capture."
    Add-NetEventPacketCaptureProvider -SessionName $sessionName -CaptureType BothPhysicalAndSwitch -Level 5 -TruncationLength $snapLen | Out-Null
}

#
# add ETW providers
#
foreach ($provider in $providers)
{
    try 
    {
        Write-Verbose "Adding $($provider.GUID) $(if ($provider.Name) {"($($provider.Name))"})"
        Add-NetEventProvider -SessionName $sessionName -Name "{$($provider.GUID)}" -Level $provider.Level -MatchAnyKeyword $provider.MatchAnyKeyword -EA Stop | Out-Null
    } 
    catch 
    {
        Write-Warning "Could not add provider $($provider.GUID)`: $_"
    }
}

#
# Start the session and optionally wait for the user to stop the session
#
Write-Verbose "Starting capture session."
try
{
    Start-NetEventSession $sessionName -EA Stop
    Write-Debug "Capture session successfully started."
}
catch
{
    return (Write-Error "Failed to start the NetEventSession: $_" -EA Stop)
}


# Prompt if -NoPrompt is not present
# Two negatives make a positive, it's the Microsoft way!
if (-NOT $NoPrompt.IsPresent)
{
    # repro the issue then press q to stop the trace
    Write-Host -ForegroundColor Green "`n`The data collection has started.`n`nReproduce the issue now and then press 'q' to stop tracing.`n`n"

    do 
    {
        $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } until ($x.Character -eq 'q')

    # stop tracing
    Write-Verbose "Stopping $sessionName."
    Stop-NetEventSession $sessionName | Out-Null
    Remove-NetEventSession $sessionName | Out-Null

    # run collectlogs.ps1 when -CollectLogs set
    if ($CollectLogs.IsPresent)
    {
        Write-Verbose "Trying to run collectlogs.ps1"
        $BaseDir = "c:\k\debug"

        # is collectlogs.ps1 in $baseDir?
        $isCLFnd = Get-Item "$BaseDir\collectlogs.ps1" -EA SilentlyContinue

        if (-NOT $isCLFnd)
        {
            Write-Verbose "Collectlogs.ps1 not found. Attempting to download."
            # try to download collectlogs.ps1
            try 
            {
                $isCLFnd = Get-WebFile -URI 'https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/debug/collectlogs.ps1' -savePath "$BaseDir" -fileName 'collectlogs.ps1'
            }
            catch 
            {
                return (Write-Warning "The trace was successful but collectlogs failed to download: $_" -EA Stop)
            }
        }
        else 
        {
            $isCLFnd = $isCLFnd.FullName    
        }

        # execute collectlogs.ps1
        if ($isCLFnd)
        {
            Write-Host "Running collectlogs.ps1."
            # redirecting as much of the collectlog output to the success stream for collection
            $clResults = &$isCLFnd *>&1 | ForEach-Object ToString
        }
    }

    Write-Host -ForegroundColor Green "`n`nAll done! The data is located at:`n`t- $EtlFile $(if ($clResults) {"`n`t- $($clResults[-1].Substring(22))"})"
}
else
{
    Write-Host -ForegroundColor Yellow "Use this command to stop capture: Stop-NetEventSession $sessionName"
    Write-Host -ForegroundColor Yellow "Use this command to remove capture: Remove-NetEventSession $sessionName"
    Write-Host -ForegroundColor Yellow "The data file will be located at $EtlFile."
}