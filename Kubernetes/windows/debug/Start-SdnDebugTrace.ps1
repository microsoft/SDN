#Requires -RunAsAdministrator

[CmdletBinding()]
param
(
    [Parameter(Position=0)]
    [ValidateSet("Lite", "Normal", "Full")]
    [string]
    $Scenario = "Normal",

    # Path with filename where the ETL file will be saved. Format: <path>\<filename>.etl
    [Parameter(Position=1)]
    [string]
    $EtlFile = "C:\server.etl",

    # How many bytes of the packet to collect. Default is 256 bytes to collect encapsulated headers.
    [Parameter(Position=2)]
    [int]
    $snapLen = 256,

    # Maximum file size in megabytes. 0 means that there is no maximum
    [Parameter(Position=3)]
    [int]
    $maxFileSize = 500,

    # Path to where the log files will be written.
    [Parameter(Position=1)]
    [string]
    $LogPath = $PSScriptRoot,

    # Does not prompt/pause execution and wait on user input.
    [switch]
    $NoPrompt,

    # Does not collect network packets.
    [switch]
    $NoPackets,

    # Collects logs after user presses q to stop tracing. Ignored when -NoPrompt set.
    [switch]
    $NoLogs
)

begin {
    ### FUNCTIONS ###
    #region
    # Downloads a file from the Internet.
    # Returns the full path to the download.
    # This function is needed to download supporting files when they are missing.
    function Get-WebFile {
        param ( 
            [string]$URI,
            [string]$Path,
            [string]$FileName
        )

        Write-Debug "Get-WebFile - Start."

        # validate path
        if ( -NOT (Test-Path "$Path" -IsValid) ) {
            return (Write-Error "The save path, $Path, is not valid. Error: $_" -EA Stop)
        }

        # create the path if missing
        if ( -NOT (Get-Item "$Path" -EA SilentlyContinue) ) {
            try {
                $null = mkdir "$Path" -Force -EA Stop
            } catch {
                return (Write-Error "The save path, $Path, does not exist and cannot be created. Error: $_" -EA Stop)
            }
            
        }

        # create the full path
        $OutFile = "$Path\$fileName"

        # use curl if it is found in the path
        # options are iwr (Invoke-WebRequest (default)), bits (Start-BitsTransfer), and curl (preferred when found)
        $dlMethods = "iwr", "curl", "bits"
        $dlMethod = "iwr"

        # switch to curl when found
        $curlFnd = Get-Command "curl.exe" -EA SilentlyContinue
        if ($curlFnd) { $dlMethod = "curl" }

        Write-Verbose "Get-WebFile - Attempting download of $URI to $OutFile"

        # did the download work?
        $dlWorked = $false

        # methods tried
        # initialize with curl because if curl is found then we're using it, if it's not found then we shouldn't try it
        $tried = @("curl")

        # loop through
        do {
            switch ($dlMethod) {
                # tracks whether 
                "curl" {
                    Write-Verbose "Get-WebFile - Download with curl."

                    Push-Location "$Path"
                    # download with curl
                    # -L = download location
                    # -o = output file
                    # -s = Silent
                    curl.exe -L $URI -o $OutFile -s
                    Pop-Location
                }

                "iwr" {
                    Write-Verbose "Get-WebFile - Download with Invoke-WebRequest."

                    # make sure we don't try to use an insecure SSL/TLS protocol when downloading files
                    Write-Debug "Get-WebFile - Disabling unsupported SSL/TLS protocls."
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12, [System.Net.SecurityProtocolType]::Tls13

                    # download silently with iwr
                    $oldProg = $global:ProgressPreference
                    $Global:ProgressPreference = "SilentlyContinue"
                    $null = Invoke-WebRequest -Uri $URI -OutFile "$OutFile" -MaximumRedirection 5 -PassThru
                    $Global:ProgressPreference = $oldProg
                }

                "bits" {
                    Write-Verbose "Get-WebFile - Download with Start-BitsTransfer."
                    
                    # download silently with iwr
                    $oldProg = $global:ProgressPreference
                    $Global:ProgressPreference = "SilentlyContinue"
                    $null = Start-BitsTransfer -Source $URI -Destination "$OutFile"
                    $Global:ProgressPreference = $oldProg
                }

                Default { return (Write-Error "An unknown download method was selected. This should not happen. dlMethod: $_" -EA Stop) }
            }

            # is there a file, any file, then consider this a success
            $dlFnd = Get-Item "$OutFile" -EA SilentlyContinue

            if ( -NOT $dlFnd ) {
                # change download method and try again
                Write-Verbose "Failed to download using $dlMethod."

                if ($tried.Count -lt $dlMethods.Count) {
                    if ($dlMethod -notin $tried) {
                        $tried += $dlMethod
                        Write-Verbose "Get-WebFile - Added $dlMethod to tried: $($tried -join ', ')"
                    }

                    :dl foreach ($dl in $dlMethods) { 
                        if ($dl -notin $tried) { 
                            Write-Verbose "Get-WebFile - Switching to $dl method."
                            $dlMethod = $dl
                            $tried += $dl
                            break dl
                        }
                    }
                } else {
                    return (Write-Error "The download has failed!" -EA Stop)
                }
            } else {
                # exit the loop
                $dlWorked = $true
            }
        } until ($dlWorked)

        Write-Verbose "Get-WebFile - File downloaded to $OutFile."

        #Add-Log "Downloaded successfully to: $output"
        Write-Debug "Get-WebFile - Returning: $OutFile"
        Write-Debug "Get-WebFile - End."
        return $OutFile
    }

    # checks the required file and tries to download it when missing
    # this is a pre-requisite requirement before loading modules
    function Test-RequiredFile {
        [CmdletBinding()]
        param (
            [Parameter()]
            [string[]]
            $RequiredFiles,

            [Parameter()]
            [string[]]
            $Dir,

            [Parameter()]
            [string[]]
            $DlRoot
        )

        #Write-Verbose "Test-RequiredFile - "
        Write-Verbose "Test-RequiredFile - begin"

        # controls whether the test is a success
        $valid = $true

        # local path to look for files
        $lclPath = "$PSScriptRoot\$Dir"
        Write-Verbose "Test-RequiredFile - lclPath: $lclPath"

        # if the dir doesn't exist then create it and download the files in the next section
        $dirFnd = Get-Item "$lclPath" -EA SilentlyContinue
        if (-NOT $dirFnd) {
            # create the dir
            try {
                $null = mkdir "$lclPath" -Force -EA Stop
                Write-Verbose "Test-RequiredFile - Created $lclPath"
            } catch {
                return ( Write-Error "Failed to create the $Dir directory. Error: $_" -EA Stop )
            }
        }

        # look for the files locally, try to download if missing
        foreach ($file in $RequiredFiles) {
            # looking
            $flObj = Get-Item "$lclPath\$file" -EA SilentlyContinue
            if ( -NOT $flObj ) {
                # try to download
                try {
                    $flStr = Get-WebFile -URI "$DlRoot\$file" -Path $lclPath -FileName $file

                    # double check
                    $flObj = Get-Item "$flStr" -EA SilentlyContinue

                    if ( -NOT $flObj ) {
                        Write-Verbose "Test-RequiredFile - Failed to validate file: $file"
                        $valid = $false
                    }
                } catch {
                    $valid = $false
                    Write-Warning "Failed to download $file. URL: $DlRoot\$file"
                }
            } else {
                Write-Verbose "Test-RequiredFile - Found file: $file"
            }
        }



        Write-Verbose "Test-RequiredFile - end"
        return $valid
    }

    #endregion FUNCTIONS

    #Write-Verbose "Start-SdnDebug Tracing - "
    Write-Verbose "Start-SdnDebug Tracing - Pre-requisite work."

    # the repo root
    $sdnDebugRepoRoot = 'https://raw.githubusercontent.com/JamesKehr/SDN/master/Kubernetes/windows/debug'

    # look for library files
    $libFiles  = "libClass.psm1", "libFunction.psm1", "libLogging.psm1"
    $libDir    = "lib"
    $libDlRoot = "$sdnDebugRepoRoot/lib"
    Write-Verbose "Start-SdnDebug Tracing - Validating lib files."
    $checkLib  = Test-RequiredFile -RequiredFiles $libFiles -Dir $libDir -DlRoot $libDlRoot


    # look for profile files
    $profileFiles   = "hns_full.json", "hns_normal.json", "hns_lite.json"
    $profilesDir    = "profiles"
    $profilesDlRoot = "$sdnDebugRepoRoot/profiles"
    Write-Verbose "Start-SdnDebug Tracing - Validating profile files."
    $checkProfiles  = Test-RequiredFile -RequiredFiles $profileFiles -Dir $profilesDir -DlRoot $profilesDlRoot

    if ( $checkLib -eq $false -or $checkProfiles -eq $false ) {
        return ( Write-Warning @"
Failed to find or download a required file. Please download the required files and try again:
`t- URL: $libDlRoot
`t- Sub-directory: lib
`t`t- $($libFiles -join "`n`t`t- ")
`t- URL: $profilesDlRoot
`t- Sub-directory: profiles
`t`t- $($profileFiles -join "`n`t`t- ")
"@ 
        )
    } else {
        Write-Verbose "Start-SdnDebug Tracing - All files validated. Proceeding with tracing."
    }


    ### load lib ###
    foreach ($file in $libFiles) {
        try {
            Write-Verbose "Start-SdnDebugTracing - Importing module: $file"
            Import-Module "$PSScriptRoot\$libDir\$file" -EA Stop
        } catch {
            return (Write-Error "Failed to import a required module: $PSScriptRoot\$libDir\$file")
        }
    }

    ### start libLogging ###

    Start-Logging -ModuleName "Start-SdnDebugTracing" -LogPath $LogPath

    ### start using libLogging cmdlets after this point ###
    Write-Log "Begin"

    Write-Log "Loading the hns_$Scenario capture profile."
    try {
        $providers = Import-HnsProfile "$PSScriptRoot\$profilesDir\hns_$Scenario`.json"
    } catch {
        Write-LogError -Text "Failed to load providers. Error: $_" -Code "PROVIDER_LOAD_FAILURE"
    }


    ## CONSTANTS ##
    # capture name
    $sessionName = 'HnsPacketCapture'

    Write-Log "Found $($providers.Count) providers."
    Write-Log "Begin - End"
}

process {
    Write-Log "Process - Begin"
    
    ## setup the trace
    #
    # Stop any existing session and create a new session
    #
    Write-Log "Cleaning up any failed $sessionName sessions."
    Stop-NetEventSession $sessionName -ErrorAction Ignore | Out-Null
    Remove-NetEventSession $sessionName -ErrorAction Ignore | Out-Null

    #
    # create capture session
    #
    try {
        Write-Log "Creating the $sessionName capture session."
        New-NetEventSession $sessionName -CaptureMode SaveToFile -MaxFileSize $maxFileSize -LocalFilePath $EtlFile -EA Stop | Out-Null
    } catch {
        return (Write-Error "Failed to create the NetEventSession: $_" -EA Stop)
    }

    #
    # add packet capture when -NoPackets not in use
    #
    if (-NOT $NoPackets.IsPresent) {
        Write-Log "Adding packet capture."
        Add-NetEventPacketCaptureProvider -SessionName $sessionName -CaptureType BothPhysicalAndSwitch -Level 5 -TruncationLength $snapLen | Out-Null
    }

    #
    # add ETW providers
    #
    foreach ($provider in $providers) {
        try {
            Write-Log "Adding $($provider.GUID) $(if ($provider.Name) {"($($provider.Name))"})"
            Add-NetEventProvider -SessionName $sessionName -Name "{$($provider.GUID)}" -Level $provider.Level -MatchAnyKeyword $provider.MatchAnyKeyword -EA Stop | Out-Null
        } catch {
            Write-LogWarning "Could not add provider $($provider.GUID)`: $_" -Code "PROVIDER_ADD_FAILURE"
        }
    }

    #
    # Start the session and optionally wait for the user to stop the session
    #
    Write-Log "Starting capture session."
    try {
        Start-NetEventSession $sessionName -EA Stop
        Write-Log "Capture session successfully started."
    } catch {
        return (Write-LogError "Failed to start the NetEventSession: $_" -Code "TRACE_START_FAILURE")
    }

    
    # Prompt if -NoPrompt is not present
    # Two negatives make a positive, it's the Microsoft way!
    if (-NOT $NoPrompt.IsPresent) {
        # repro the issue then press q to stop the trace
        Write-Host -ForegroundColor Green "`n`The data collection has started.`n`nReproduce the issue now and then press 'q' to stop tracing.`n`n"

        do {
            $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        } until ($x.Character -eq 'q')

        # stop tracing
        Write-Log "Stopping $sessionName."
        Stop-NetEventSession $sessionName | Out-Null
        Remove-NetEventSession $sessionName | Out-Null

        # run collectlogs.ps1 when -CollectLogs set
        if ( -NOT $NoLogs.IsPresent ) {
            Write-Log "Trying to run collectlogs.ps1"
            $BaseDir = "c:\k\debug"

            # make sure the dir is created
            $null = mkdir $BaseDir -Force -EA SilentlyContinue

            # is collectlogs.ps1 in $baseDir?
            $isCLFnd = Get-Item "$BaseDir\collectlogs.ps1" -EA SilentlyContinue

            if (-NOT $isCLFnd) {
                Write-Log "Collectlogs.ps1 not found. Attempting to download."
                # try to download collectlogs.ps1
                try {
                    $isCLFnd = Get-WebFile -URI 'https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/debug/collectlogs.ps1' -Path "$BaseDir" -FileName 'collectlogs.ps1'
                } catch  {
                    return (Write-LogWarning "The trace was successful but collectlogs failed to download: $_" -Code "COLLECTLOGS_DOWNLOAD_FAILED")
                }
            } else {
                $isCLFnd = $isCLFnd.FullName    
            }

            # execute collectlogs.ps1
            if ($isCLFnd) {
                Write-Host "Running collectlogs.ps1."
                # redirecting as much of the collectlog output to the success stream for collection
                $clResults = &$isCLFnd *>&1 | ForEach-Object ToString
            }
        }

        Write-Host -ForegroundColor Green "`n`nAll done! The data is located at:`n`t- $EtlFile $(if ($clResults) {"`n`t- $($clResults[-1].Substring(22))"})"
    } else {
        Write-Host -ForegroundColor Yellow "Use this command to stop capture: Stop-NetEventSession $sessionName"
        Write-Host -ForegroundColor Yellow "Use this command to remove capture: Remove-NetEventSession $sessionName"
        Write-Host -ForegroundColor Yellow "The data file will be located at $EtlFile."
    }

    Write-Log "Process - End"
}

end {
    Write-Log "End - Begin"

    Write-Log "End - Work complete!"

    #############################################
    ### DO NOT USE libLogging past this point ###
    #############################################
    Close-Logging -ModuleName "Start-SdnDebugTracing"

}