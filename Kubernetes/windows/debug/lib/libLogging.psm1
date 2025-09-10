# PowerShell logging module
#requires -Version 5.1

using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Collections.Concurrent



<#

TO-DO:


#>



enum LogType {
    main
    warning
    error
}

class Logging {
    ### PROPERTIES/CONSTRUCTOR ###
    #region

    # All logged text goes into the main stream
    [ConcurrentQueue[string]]
    $MainStream

    # Warning text also goes into the warning stream
    [ConcurrentQueue[string]]
    $WarningStream

    # Error text also goes into the error stream
    [ConcurrentQueue[string]]
    $ErrorStream

    # Enforces no writing of the log events to file.
    [bool]
    $NoWrite

    # Where do the logs get written to?
    # Provide the path where the three log files will be written to
    [string]
    $LogPath

    # Name of the module. 
    hidden
    [string]
    $Module

    hidden
    [string]
    $ParentModule

    # Name of the MainStream file
    hidden
    [string]
    $MainFile

    # Name of the WarningStream file
    hidden
    [string]
    $WarningFile

    # Name of the MainStream file
    hidden
    [string]
    $ErrorFile

    # since the MainStream does some async writing the number of events in MainStream does not accurately reflect 
    # the total number of events added to MainStream
    # this variable tracks the total number of events
    hidden
    [uint64]
    $MainStreamTotal

    # prevents multiple writers from executing
    hidden
    [bool]
    $Writing

    # blocks adding new entries to logs once Close() has been called
    hidden
    [bool]
    $Closing

    #endregion

    ## CONSTRUCTOR ##
    #region

    Logging() {
        $this.MainStream    = [ConcurrentQueue[string]]::new()
        $this.WarningStream = [ConcurrentQueue[string]]::new()
        $this.ErrorStream   = [ConcurrentQueue[string]]::new()

        $this.MainStreamTotal = 0

        # setup logging files
        # use PWD for the LogPath
        $this.LogPath = $PWD.Path

        # stream log file names
        $stamp = $this.Filestamp()
        $this.MainFile    = "MainStream_$stamp`.log"
        $this.WarningFile = "WarningStream_$stamp`.log"
        $this.ErrorFile   = "ErrorStream_$stamp`.log"
        $this.Module      = "Validate-SoQCertificate"
        $this.Closing     = $false
        $this.Writing     = $false

        # create the files
        try {
            # the PWD should exist...
            $null = New-Item "$($this.LogPath)\$($this.MainFile)" -ItemType File -EA Stop
            $null = New-Item "$($this.LogPath)\$($this.WarningFile)" -ItemType File -EA Stop
            $null = New-Item "$($this.LogPath)\$($this.ErrorFile)" -ItemType File -EA Stop

            $this.NoWrite     = $false
        } catch {
            Write-Error "Failed to create a logging file: $_" -EA Stop
            $this.NoWrite     = $true
        }
    }

    Logging([string]$loggingPath) {
        $this.MainStream    = [ConcurrentQueue[string]]::new()
        $this.WarningStream = [ConcurrentQueue[string]]::new()
        $this.ErrorStream   = [ConcurrentQueue[string]]::new()
        
        $this.MainStreamTotal = 0

        # setup logging files
        # test logpath
        if ( (Test-Path "$loggingPath" -IsValid) ) {
            $this.LogPath = $loggingPath
        } else {
            $this.LogPath = $PWD.Path
        }
        

        # stream log file names
        $stamp = $this.Filestamp()
        $this.MainFile    = "MainStream_$stamp`.log"
        $this.WarningFile = "WarningStream_$stamp`.log"
        $this.ErrorFile   = "ErrorStream_$stamp`.log"
        $this.Closing     = $false
        $this.Writing     = $false
        $this.Module      = "Validate-SoQCertificate"

        # create the files
        try {
            # make sure the LogPath is there
            $null = mkdir "$($this.LogPath)" -Force -EA Stop

            $null = New-Item "$($this.LogPath)\$($this.MainFile)" -ItemType File -Force -EA Stop
            $null = New-Item "$($this.LogPath)\$($this.WarningFile)" -ItemType File -Force -EA Stop
            $null = New-Item "$($this.LogPath)\$($this.ErrorFile)" -ItemType File -Force -EA Stop
        } catch {
            Write-Error "Failed to create a logging file: $_" -EA Stop
        }
    }

    Logging([bool]$writeToFile) {
        $this.MainStream    = [ConcurrentQueue[string]]::new()
        $this.WarningStream = [ConcurrentQueue[string]]::new()
        $this.ErrorStream   = [ConcurrentQueue[string]]::new()

        $this.MainStreamTotal = 0

        # setup logging files
        # use PWD for the LogPath if writeToFile is $true
        if ($writeToFile) {
            $this.LogPath = $PWD.Path

            # stream log file names
            $stamp = $this.Filestamp()
            $this.MainFile    = "MainStream_$stamp`.log"
            $this.WarningFile = "WarningStream_$stamp`.log"
            $this.ErrorFile   = "ErrorStream_$stamp`.log"

            # create the files
            try {
                # the PWD should exist...
                $null = New-Item "$($this.LogPath)\$($this.MainFile)" -ItemType File -EA Stop
                $null = New-Item "$($this.LogPath)\$($this.WarningFile)" -ItemType File -EA Stop
                $null = New-Item "$($this.LogPath)\$($this.ErrorFile)" -ItemType File -EA Stop
                $this.NoWrite     = $false
            } catch {
                Write-Error "Failed to create a logging file: $_" -EA Stop
                $this.NoWrite     = $true
            }
        } else {
            Write-Verbose "No write mode"
            $this.LogPath = $null

            $this.MainFile    = $null
            $this.WarningFile = $null
            $this.ErrorFile   = $null
            $this.NoWrite     = $true
        }

        $this.Module      = "Validate-SoQCertificate"
        $this.Closing     = $false
        $this.Writing     = $false
    }

    Logging([string]$loggingPath, [string]$moduleName) {
        $this.MainStream    = [ConcurrentQueue[string]]::new()
        $this.WarningStream = [ConcurrentQueue[string]]::new()
        $this.ErrorStream   = [ConcurrentQueue[string]]::new()
        
        $this.MainStreamTotal = 0

        # setup logging files
        # test logpath
        if ( (Test-Path "$loggingPath" -IsValid) ) {
            $this.LogPath = $loggingPath
        } else {
            $this.LogPath = $PWD.Path
        }
        

        # stream log file names
        $stamp = $this.Filestamp()
        $this.MainFile    = "MainStream_$stamp`.log"
        $this.WarningFile = "WarningStream_$stamp`.log"
        $this.ErrorFile   = "ErrorStream_$stamp`.log"
        $this.Closing     = $false
        $this.Writing     = $false
        $this.Module      = $moduleName

        # create the files
        try {
            # make sure the LogPath is there
            $null = mkdir "$($this.LogPath)" -Force -EA Stop

            $null = New-Item "$($this.LogPath)\$($this.MainFile)" -ItemType File -Force -EA Stop
            $null = New-Item "$($this.LogPath)\$($this.WarningFile)" -ItemType File -Force -EA Stop
            $null = New-Item "$($this.LogPath)\$($this.ErrorFile)" -ItemType File -Force -EA Stop

            $this.NoWrite     = $false
        } catch {
            Write-Error "Failed to create a logging file: $_" -EA Stop
            $this.NoWrite     = $true
        }
    }

    Logging([bool]$writeToFile, [string]$moduleName) {
        $this.MainStream    = [ConcurrentQueue[string]]::new()
        $this.WarningStream = [ConcurrentQueue[string]]::new()
        $this.ErrorStream   = [ConcurrentQueue[string]]::new()

        $this.MainStreamTotal = 0

        # setup logging files
        # use PWD for the LogPath if writeToFile is $true
        if ($writeToFile) {
            $this.LogPath = $PWD.Path

            # stream log file names
            $stamp = $this.Filestamp()
            $this.MainFile    = "MainStream_$stamp`.log"
            $this.WarningFile = "WarningStream_$stamp`.log"
            $this.ErrorFile   = "ErrorStream_$stamp`.log"

            # create the files
            try {
                # the PWD should exist...
                $null = New-Item "$($this.LogPath)\$($this.MainFile)" -ItemType File -EA Stop
                $null = New-Item "$($this.LogPath)\$($this.WarningFile)" -ItemType File -EA Stop
                $null = New-Item "$($this.LogPath)\$($this.ErrorFile)" -ItemType File -EA Stop
                $this.NoWrite     = $false
            } catch {
                Write-Error "Failed to create a logging file: $_" -EA Stop
                $this.NoWrite     = $true
            }
        } else {
            Write-Verbose "No write mode"
            $this.LogPath = $null

            $this.MainFile    = $null
            $this.WarningFile = $null
            $this.ErrorFile   = $null
            $this.NoWrite     = $true
        }

        $this.Module      = $moduleName
        $this.Closing     = $false
        $this.Writing     = $false
    }

    #endregion


    ### METHOD ###
    #region

    ## NEW ##
    #region

    # this version always terminates
    NewError(
        [string]$module, 
        [string]$function, 
        [string]$code, 
        [string]$message
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($module, $function, $code, $message, "error")
            Write-Debug "txt: $txt"

            # add to the log
            $this.AddError($txt)

            # create a formatted entry without ERROR: at the beginning, because Write-Error adds that
            #$txt2 = $this.FormatEntry($module, $function, $code, $message, "main")

            $this.Close()
            #Write-Error -Message $txt -ErrorAction Stop
            throw $txt
        }
    }

    # this version optionally terminates
    NewError(
        [string]$module, 
        [string]$function, 
        [string]$code, 
        [string]$message,
        [bool]$terminate
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($module, $function, $code, $message, "error")
            Write-Debug "txt: $txt; terminating: $terminate"

            # add to the log
            $this.AddError($txt)

            if ($terminate) {
                $this.Close()
                #Write-Error -Message $txt -ErrorAction Stop
                throw $txt
            } else {
                # create a formatted entry without ERROR: at the beginning, because Write-Error adds that
                $txt2 = $this.FormatEntry($module, $function, $code, $message, "main")
                Write-Error -Message $txt2
            }
        }
    }

    # this version optionally terminates
    NewError(
        [string]$function, 
        [string]$code, 
        [string]$message,
        [bool]$terminate
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($this.Module, $function, $code, $message, "error")
            Write-Debug "txt: $txt; terminating: $terminate"

            # add to the log
            $this.AddError($txt)

            if ($terminate) {
                $this.Close()
                #Write-Error -Message $txt -ErrorAction Stop
                throw $txt
            } else {
                # create a formatted entry without ERROR: at the beginning, because Write-Error adds that
                $txt2 = $this.FormatEntry($this.Module, $function, $code, $message, "main")

                Write-Error -Message $txt2
            }
        }
    }

    # this version optionally terminates, uses the default module, and does not need a function
    NewError(
        [string]$code, 
        [string]$message,
        [bool]$terminate
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($this.Module, $null, $code, $message, "error")
            Write-Debug "txt: $txt; terminating: $terminate"

            # add to the log
            $this.AddError($txt)

            if ($terminate) {
                $this.Close()
                #Write-Error -Message $txt -ErrorAction Stop
                throw $txt
            } else {
                # create a formatted entry without ERROR: at the beginning, because Write-Error adds that
                $txt2 = $this.FormatEntry($this.Module, $null, $code, $message, "main")

                Write-Error -Message $txt2
            }
        }
    }

    # warnings never terminates
    NewWarning(
        [string]$module, 
        [string]$function, 
        [string]$code, 
        [string]$message
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($module, $function, $code, $message, "warning")

            # add to the log
            $this.AddWarning($txt)

            # create a formatted entry without WARNING: at the beginning, because Write-Warning adds that
            $txt2 = $this.FormatEntry($module, $function, $code, $message, "main")

            Write-Warning $txt2
        }
    }

    NewWarning(
        [string]$function, 
        [string]$code, 
        [string]$message
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($this.Module, $function, $code, $message, "warning")

            # add to the log
            $this.AddWarning($txt)

            # create a formatted entry without WARNING: at the beginning, because Write-Warning adds that
            $txt2 = $this.FormatEntry($this.Module, $function, $code, $message, "main")

            Write-Warning $txt2
        }
    }

    # warnings never terminate, use default module, no function
    NewWarning(
        [string]$code, 
        [string]$message
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($this.Module, $null, $code, $message, "warning")

            # add to the log
            $this.AddWarning($txt)

            # create a formatted entry without WARNING: at the beginning, because Write-Warning adds that
            $txt2 = $this.FormatEntry($this.Module, $null, $code, $message, "main")

            Write-Warning $txt2
        }
    }

    # logging never terminates
    NewLog(
        [string]$module, 
        [string]$function, 
        [string]$message
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($module, $function, "", $message, "main")
            
            # add to the log
            $this.AddLog($txt)

            # dump events to disk if there are more than 10000 lines in MainStream
            if ( $this.MainStream.Count -ge 10 ) {
                $this.UpdateLogFile()
            }
        }
    }

    NewLog(
        [string]$function, 
        [string]$message
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($this.Module, $function, "", $message, "main")
            
            # add to the log
            $this.AddLog($txt)

            # dump events to disk if there are more than 10000 lines in MainStream
            if ( $this.MainStream.Count -ge 10 ) {
                $this.UpdateLogFile()
            }
        }
    }

    NewLog(
        [string]$message
    ) {
        if ( -NOT $this.Closing) {
            # get the formatted entry
            $txt = $this.FormatEntry($this.Module, $null, "", $message, "main")
            
            # add to the log
            $this.AddLog($txt)

            # dump events to disk if there are more than 10000 lines in MainStream
            if ( $this.MainStream.Count -ge 10 ) {
                $this.UpdateLogFile()
            }
        }
    }

    #endregion NEW

    ## ADD ##
    #region
    
    # adds an event to a logging stream
    # no terminating errors come from here
    # don't use AddLog inside of AddLog
    AddLog([string]$txt) {
        if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
            Write-Verbose "$txt"

            if ( -NOT $this.NoWrite ) {
                $txt = "$($this.Timestamp())`: $txt"
                $this.IncrementMainStream()
                $this.MainStream.Enqueue($txt)
            }
        }
    }

    AddLog([string]$txt, [bool]$Timestamp) {
        if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
            Write-Verbose "$txt"

            if ( -NOT $this.NoWrite ) {
                if ( $Timestamp -eq $true ) {
                    $txt = "$($this.Timestamp())`: $txt"
                }
                
                $this.IncrementMainStream()
                $this.MainStream.Enqueue($txt)
            }
        }
    }

    # non-terminating
    hidden
    AddWarning([string]$txt) {
        if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
            $txt = "$($this.Timestamp())`: $txt" 

            $this.AddLog($txt, $false)

            if ( -NOT $this.NoWrite ) { $this.WarningStream.Enqueue($txt) }
        }
    }

    # always terminates when calling this method
    hidden
    AddError([string]$txt) {
        if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
            $txt = "$($this.Timestamp())`: $txt" 

            $this.AddLog($txt, $false)
            
            if ( -NOT $this.NoWrite ) { $this.ErrorStream.Enqueue($txt) }
        }
    }

    #endregion

    ## WRITE ##
    #region

    # !!! DO NOT call NewError, NewWarning, or NewLog in these methods !!!
    # Use Write-Verbose cmdlets if troubleshooting logging is needed.

    # dumps events from the mainstream to file for up to ~250ms or no more entries
    hidden
    UpdateLogFile() {
        <# 
            Write only when:

            1. A file write is not in progress ($this.Writing -eq $false).
            -AND-
            2. There is something to write ( -and $this.MainStream.Count -gt 0).
            -AND-
            3. Writing is enabled ( -and -NOT $this.NoWrite).

        #>
        if ( $this.Writing -eq $false -and $this.MainStream.Count -gt 0 -and -NOT $this.NoWrite ) {
            # prevent overlapping writes by setting Writing to true - simple "lock" mechanism
            $this.Writing = $true

            # create the parsed file and stream writer
            $stream = [System.IO.StreamWriter]::new("$($this.LogPath)\$($this.MainFile)", $true)

            # dequeues an object to write it to file
            # only spend ~250ms writing, max, to prevent noticeable hangs
            $sw = [System.Diagnostics.Stopwatch]::new()
            $sw.Start()
            while ( $this.MainStream.Count -gt 0 -and $sw.ElapsedMilliseconds -lt 275 ) {
                $line = ""
                
                # TryDequeue returns $true when the first element in the ConcurrentQueue was successfully dequeued to $line
                if ( $this.MainStream.TryDequeue([ref]$line) ) {
                    # write the line to file
                    $stream.WriteLine( $line )
                }
            }

            # stop the stopwatch
            $sw.Stop()

            # close the StreamWriter
            $stream.Close()

            # allow writing
            $this.Writing = $false
        }
    }

    # writes all MainStream events to file - used by Close()
    hidden
    WriteLog2File() {
        
        if ($this.MainStream.Count -gt 0) {
            $logFile = "$($this.LogPath)\$($this.MainFile)"
            
            # instance is closing so lock all other writing while the MainStream is written to file
            $this.Writing = $true
            $stream = [System.IO.StreamWriter]::new($logFile, $true)

            while ( $this.MainStream.Count -gt 0 ) {
                $line = ""
                
                # TryDequeue returns $true when the first element in the ConcurrentQueue was successfully dequeued to $line
                if ( $this.MainStream.TryDequeue([ref]$line) ) {
                    # write the line to file
                    $stream.WriteLine( $line )
                }
            }

            # close the StreamWriter
            $stream.Close()
        }
    }

    # writes all WarningStream events to file - used by Close()
    hidden
    WriteWarningLog2File() {
        if ($this.WarningStream.Count -gt 0) {
            $warnFile = "$($this.LogPath)\$($this.WarningFile)"

            $stream = [System.IO.StreamWriter]::new("$warnFile")

            while ( $this.WarningStream.Count -gt 0 ) {
                $line = ""
                
                # TryDequeue returns $true when the first element in the ConcurrentQueue was successfully dequeued to $line
                if ( $this.WarningStream.TryDequeue([ref]$line) ) {
                    # write the line to file
                    $stream.WriteLine( $line )
                }
            }

            # close the StreamWriter
            $stream.Close()
        }
    }

    # writes all ErrorStream events to file - used by Close()
    hidden
    WriteErrorLog2File() {
        if ($this.ErrorStream.Count -gt 0) {
            $errFile = "$($this.LogPath)\$($this.ErrorFile)"

            $stream = [System.IO.StreamWriter]::new("$errFile")

            while ( $this.ErrorStream.Count -gt 0 ) {
                $line = ""
                
                # TryDequeue returns $true when the first element in the ConcurrentQueue was successfully dequeued to $line
                if ( $this.ErrorStream.TryDequeue([ref]$line) ) {
                    # write the line to file
                    $stream.WriteLine( $line )
                }
            }

            # close the StreamWriter
            $stream.Close()
        }
    }

    #endregion WRITE

    ## UTILITY ##
    #region

    # get a timestamp
    [string]
    hidden
    Timestamp() {
        return (Get-Date -Format "yyyyMMdd-HH:mm:ss.ffffff")
    }

    # get a timestamp for a file name
    [string]
    hidden
    Filestamp() {
        return (Get-Date -Format "yyyyMMdd_HHmmss")
    }

    IncrementMainStream() {
        $this.MainStreamTotal = $this.MainStreamTotal + 1
    }

    [string]
    hidden
    FormatEntry(
        [string]$mod, 
        [string]$function, 
        [string]$code, 
        [string]$message,
        [LogType]$logType
    ) {
        $str = ""

        # modules with a dash (-) are treated as cmdlet names, and not class related modules
        if ($mod -match '-') {
            $modIsFunc = $true
        } else {
            $modIsFunc = $false
        }

        # when the module is null and the function contains something, swap the two
        if (-NOT [string]::IsNullOrEmpty($function) -and [string]::IsNullOrEmpty($mod)) {
            $mod = $function
            $function = $null
        }

        # there must always be a module
        switch ($logType) {
            "error"   { 
                # do not wrap in [] if the module name contains a dash (-)... assume this is a function
                if ($modIsFunc) {
                    $str = "ERROR: $mod" 
                } else {
                    $str = "ERROR: [$mod]" 
                }
            }
            
            "warning" { 
                if ($modIsFunc) {
                    $str = "WARNING: $mod" 
                } else {
                    $str = "WARNING: [$mod]" 
                }
            }

            default   { 
                if ($modIsFunc) {
                    $str = "$mod"
                } else {
                    $str = "[$mod]"
                }
                
            }
        }
        #Write-Host "2 - mod: $module, func: $function, code: $code, mess: $message, type: $logtype, str: $str"
        
        # function is options
        if ( -NOT [string]::IsNullOrEmpty($function) -and -NOT $modIsFunc) {
            $str = [string]::Concat($str, ".$function - ")
        } elseif ( -NOT [string]::IsNullOrEmpty($function) -and $modIsFunc ) {
            $str = [string]::Concat($str, " - [$function] - ")
        } else {
            $str = [string]::Concat($str, " - ")
        }

        # add the message (not optional)
        $str = [string]::Concat($str, $message)

        # code is optional
        if ( -NOT [string]::IsNullOrEmpty($code) ) {
            $str = [string]::Concat($str, " code: $code")
        }
        return $str
    }

    Close() {
        # set Closing to $true
        $this.Closing = $true

        # wait for 100ms to make sure any outstanding work is completed
        Start-Sleep -Milliseconds 100

        # are there outstanding writes?
        if ( $this.Writing ) {
            $sw = [System.Diagnostics.Stopwatch]::new()
            $sw.Start()

            do {
                Start-Sleep -Milliseconds 50
            } until ($this.Writing -eq $false -or $sw.ElapsedMilliseconds -gt 500)

            # if still Writing then the StreamWriter may have experiences a failure
            # rename the MainFile and continue writing the events to the alternate file
            if ( $this.Writing ) { 
                $this.MainFile = "$($this.MainFile.Split('.')[0])_StreamFailure.log" 
                $null = New-Item "$($this.LogPath)\$($this.MainFile)" -ItemType File -Force
            }
        }

        # Write all the logs to file
        # now handled by the Clear() method
        
        # clear the log data
        $this.Clear()

        # clean up 0B files
        $logFileobj = Get-Item "$($this.LogPath)\$($this.MainFile)" -EA SilentlyContinue
        $errFileObj = Get-Item "$($this.LogPath)\$($this.ErrorFile)" -EA SilentlyContinue
        $warnFileObj = Get-Item "$($this.LogPath)\$($this.WarningFile)" -EA SilentlyContinue

        if ( $logFileobj.Length -eq 0 ) { Remove-Item $logFileobj -Force -EA SilentlyContinue }
        if ( $errFileObj.Length -eq 0 ) { Remove-Item $errFileObj -Force -EA SilentlyContinue }
        if ( $warnFileObj.Length -eq 0 ) { Remove-Item $warnFileObj -Force -EA SilentlyContinue }

        # set all variables to $null
        $this.MainFile = $null
        $this.MainStream = $null

        $this.WarningFile = $null
        $this.WarningStream = $null

        $this.ErrorFile = $null
        $this.ErrorStream = $null

        $this.Closing = $null
        $this.Writing = $null

        $this.LogPath = $null
    }

    Clear() {
        # clear all the streams by dequeing everything with the write log methods
        # the Clear() method for ConcurrentQueue does not work on PowerShell 5.1/.NET 4.8.1, so this acts as a workaround and a way to prevent log loss rolled into one
        if ( -NOT $this.NoWrite ) {
            $this.AddLog("[Logging].Clear - Writing logs to file.")
            $this.WriteErrorLog2File()
            $this.WriteWarningLog2File()
            $this.WriteLog2File()
        }

        $this.MainStreamTotal = 0
    }
    #endregion UTILITY

    #endregion METHODS
}

#region
$TypeData = @{
    TypeName   = 'Logging'
    MemberType = 'ScriptProperty'
    MemberName = 'MainCount'
    Value      = {$this.MainStreamTotal}
}

Update-TypeData @TypeData -EA SilentlyContinue

$TypeData = @{
    TypeName   = 'Logging'
    MemberType = 'ScriptProperty'
    MemberName = 'WarningCount'
    Value      = {$this.WarningStream.Count}
}

Update-TypeData @TypeData -EA SilentlyContinue

$TypeData = @{
    TypeName   = 'Logging'
    MemberType = 'ScriptProperty'
    MemberName = 'ErrorCount'
    Value      = {$this.ErrorStream.Count}
}

Update-TypeData @TypeData -EA SilentlyContinue


$TypeData = @{
    TypeName   = 'Logging'
    DefaultDisplayPropertySet = 'MainCount', 'WarningCount', 'ErrorCount', 'LogPath'
}

Update-TypeData @TypeData -EA SilentlyContinue
#endregion

#endregion LOGGING

<#
    $script:libLogging.NewLog("")
    $script:libLogging.NewLog("module", function", "message")
    $script:libLogging.NewLog("function", "message")
    $script:libLogging.NewError("code", "", $false)
    $script:libLogging.NewWarning("code", "")
#>

function script:Start-Logging {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ModuleName,

        [Parameter()]
        [string]
        $LogPath = $null
    )

    Write-Verbose "Start-Logging - ModuleName: $ModuleName"
    Write-Verbose "Start-Logging - LogPath: $LogPath"
    # do not write the log unless LogPath has a valid path
    if ( [string]::IsNullOrEmpty($LogPath) ) {
        Write-Verbose "No log write mode."

        # change the module if the log var exists
        if ($script:libLogging) {
            $oldLogMod = $script:libLogging.Module
            Write-Verbose "oldLogMod: $oldLogMod"
            $script:libLogging.Module = $moduleName
        # otherwise create a new log
        } else {
            Write-Verbose "New log file."
            $oldLogMod = $null
            # create new log with NoWrite set to $true
            $script:libLogging = [Logging]::new($false, $moduleName)
            $script:libLogging.ParentModule = $ModuleName
            $script:libLogging.NewLog("Start-Logging - Parent module: $($script:libLogging.ParentModule)")

        }
    } else {
        Write-Verbose "Write logs to path: $LogPath"
    
        # LogPath must be a directory
        $lpIsDir = Get-Item "$LogPath" -EA SilentlyContinue
        if ( $lpIsDir -and -NOT $lpIsDir.PSIsContainer ) { $LogPath = $PWD.Path }

        # create the dir if needed
        try {
            $null = New-Item "$LogPath" -ItemType Directory -Force -EA Stop
        } catch {
            # use PWD instead
            $LogPath = $PWD.Path
        }

        if ($logFnd) {
            $oldLogMod = $script:libLogging.Module
            $script:libLogging.Module = $moduleName
        # otherwise create a new log
        } else {
            $oldLogMod = ""
            # create new log with NoWrite set to $true
            $script:libLogging = [Logging]::new($LogPath, $moduleName)
            $script:libLogging.ParentModule = $ModuleName
            $script:libLogging.NewLog("Start-Logging - Parent module: $($script:libLogging.ParentModule)")
        } 
    }

    return $oldLogMod
}

function script:Close-Logging {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ModuleName,

        [Parameter()]
        [string]
        $oldLogMod = $null
    )

    # close the log if the parent module calls Close-Logging
    $script:libLogging.NewLog("Close-Logging - ModuleName: $ModuleName; Parent: $($script:libLogging.ParentModule)")
    $script:libLogging.NewLog("Close-Logging - oldLogMod: $oldLogMod")
    if ( $ModuleName -eq $script:libLogging.ParentModule ) { # -or [string]::IsNullOrEmpty($oldLogMod)
        $script:libLogging.NewLog("Close-Logging - Closing log.")
        $script:libLogging.Close()
    # swap module name back when returning to a caller
    } else {
        $script:libLogging.NewLog("Close-Logging - Change log module back to $oldLogMod")
        $script:libLogging.Module = $oldLogMod
    }
    
}

function script:Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Text,

        [Parameter()]
        [string]
        $Module = $null,

        [Parameter()]
        [string]
        $Function = $null
    )

    # most of the work is handled by the class.
    # proceed only if there's something to log and let the class figure out the rest.
    if ( -NOT [string]::IsNullOrEmpty($Text) -and -NOT [string]::IsNullOrWhiteSpace($Text) ) {
        # write with module and function from args when module and function are not null/empty
        if ( -NOT [string]::IsNullOrEmpty($Module) -and -NOT [string]::IsNullOrEmpty($Function) ) {
            $script:libLogging.NewLog($Text, $Function, $Module)
        # write with the function 
        } elseif ( [string]::IsNullOrEmpty($Module) -and -NOT [string]::IsNullOrEmpty($Function) ) {
            $script:libLogging.NewLog($Text, $Function)
        # write just the text
        } else {
            $script:libLogging.NewLog($Text)
        }
    } else {
        Write-Debug "Write-Log - No text passed."
    }
}


<#

# warnings never terminate, use default module, no function
    NewWarning(
        [string]$code, 
        [string]$message
    )

    NewWarning(
        [string]$module, 
        [string]$function, 
        [string]$code, 
        [string]$message
    )

    NewWarning(
        [string]$function, 
        [string]$code, 
        [string]$message
    )

#>
function script:Write-LogWarning {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Text,

        [Parameter(Mandatory)]
        [string]
        $Code,

        [Parameter()]
        [string]
        $Module = $null,

        [Parameter()]
        [string]
        $Function = $null
    )

    # most of the work is handled by the class.
    # proceed only if there's something to log and let the class figure out the rest.
    if ( (-NOT [string]::IsNullOrEmpty($Text) -and -NOT [string]::IsNullOrWhiteSpace($Text)) -and 
         (-NOT [string]::IsNullOrEmpty($Code) -and -NOT [string]::IsNullOrWhiteSpace($Code)) ) {

        # write with module and function from args when module and function are not null/empty
        if ( -NOT [string]::IsNullOrEmpty($Module) -and -NOT [string]::IsNullOrEmpty($Function) ) {
            $script:libLogging.NewWarning($Module, $Function, $Code, $Text)
        # write with the function 
        } elseif ( [string]::IsNullOrEmpty($Module) -and -NOT [string]::IsNullOrEmpty($Function) ) {
            $script:libLogging.NewWarning($Function, $Code, $Text)
        # write just the text
        } else {
            $script:libLogging.NewWarning($Code, $Text)
        }
    } else {
        Write-Debug "Write-LogWarning - No text or code passed. Text: $Text; Code: $Code"
    }
}


<#
# this version always terminates
   NewError(
        [string]$code, 
        [string]$message,
        [bool]$terminate
    )

    NewError(
        [string]$function, 
        [string]$code, 
        [string]$message,
        [bool]$terminate
    )

    NewError(
        [string]$module, 
        [string]$function, 
        [string]$code, 
        [string]$message,
        [bool]$terminate
    )

#>
function script:Write-LogError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Text,

        [Parameter(Mandatory)]
        [string]
        $Code,

        [Parameter()]
        [string]
        $Module = $null,

        [Parameter()]
        [string]
        $Function = $null,

        [Parameter()]
        [switch]
        $NonTerminating
    )

    # most of the work is handled by the class.
    # proceed only if there's something to log and let the class figure out the rest.
    if ( (-NOT [string]::IsNullOrEmpty($Text) -and -NOT [string]::IsNullOrWhiteSpace($Text)) -and 
         (-NOT [string]::IsNullOrEmpty($Code) -and -NOT [string]::IsNullOrWhiteSpace($Code)) ) {

        # write with module and function from args when module and function are not null/empty
        if ( -NOT [string]::IsNullOrEmpty($Module) -and -NOT [string]::IsNullOrEmpty($Function) ) {
            $script:libLogging.NewError($Module, $Function, $Code, $Text, !$NonTerminating.IsPresent)
        # write with the function 
        } elseif ( [string]::IsNullOrEmpty($Module) -and -NOT [string]::IsNullOrEmpty($Function) ) {
            $script:libLogging.NewError($Function, $Code, $Text, !$NonTerminating.IsPresent)
        # write just the text
        } else {
            $script:libLogging.NewError($Code, $Text, !$NonTerminating.IsPresent)
        }
    } else {
        Write-Debug "Write-LogError - No text or code passed. Text: $Text; Code: $Code"
    }
}
