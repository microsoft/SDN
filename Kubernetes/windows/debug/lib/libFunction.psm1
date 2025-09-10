using namespace System.Collections.Generic
using module .\libClass.psm1


# Downloads a file from the Internet.
# Returns the full path to the download.
function Get-WebFile
{
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


function Import-HnsProfile {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $file
    )

    #Write-Log "Import-HnsProfile - "
    Write-Log "Import-HnsProfile - Begin"

    # does the file exist?
    $fileObj = Get-Item "$file" -EA SilentlyContinue

    if (-NOT $fileObj) {
        throw "Failed to find the profile file: $file"
    }
    Write-Log "Import-HnsProfile - File found: $file"

    # is the file JSON?
    if ($fileObj.Extension -ne ".json") {
        throw "The profile file is invalid. The profile must be a JSON file. File extension found: $($fileObj.Extension)"
    }

    # import the JSON
    $profiles = Get-Content $fileObj | ConvertFrom-Json

    # make sure the profile layout is correct
    if ($profiles.Count -le 0) {
        throw "No profiles were found in the file."
    }

    # the properties must be: 
    $propList = 'Name', 'GUID', 'Level', 'MatchAnyKeyword' | Sort-Object
    $propFnd = $profiles | Get-Member -Type NoteProperty | ForEach-Object Name | Sort-Object

    $propValid = $true
    foreach ($pl in $propList) {
        if ($pl -notin $propFnd) {
            Write-Warning "$pl was not found in the profile."
            $propValid = $false
        }
    }

    if ($propValid -eq $false) {
        throw "The profile object is invalid."
    }

    # finally... create a Provider object
    $props = [List[Provider]]::new()

    foreach ($p in $profiles) {
        # try to create the Provider object
        try {
            [string]$Name            = $p.Name
            [guid]$GUID              = $p.GUID
            [byte]$Level             = $p.Level
            [uint64]$MatchAnyKeyword = $p.MatchAnyKeyword

            $tmpProv = [Provider]::new($Name, $GUID, $Level, $MatchAnyKeyword)
            $props.Add($tmpProv)

            Remove-Variable tmpProv, Name, GUID, Level, MatchAnyKeyword -EA SilentlyContinue
        } catch {
            return ( Write-Error "Failed to convert the profile. Error: $_" -EA Stop )
        }
    }

    return $props
}
