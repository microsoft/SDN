<#
.SYNOPSIS
    Monitor a target system for ICMP, TCP, and UDP network blackout.
#>
param(
    [Parameter(Mandatory=$true)]
    [String] $Target,

    [Parameter(Mandatory=$true)]
    [PSCredential] $Credential,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1000, [Int]::MaxValue)]
    [Int] $BlackoutThreshold = 1000, # ms

    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [String] $BinDir = $PSScriptRoot
)

$pingCmd = {
    param($Target)

    while ($true) {
        $a = Get-Date
        $b = ping -n 1 -w 50 $Target
        Write-Output "$($a.Ticks),$($b[2])"
    }
}

$ctsTrafficCmd = {
    param($BinDir, $Target, $Protocol, $Role)

    $bufferSize = 64 # bytes
    $rateLimitPeriod = 1 # ms

    # Allows 1 packet per rateLimitPeriod
    $rateLimit = $bufferSize * (1000 / $rateLimitPeriod)

    if ($Protocol -eq "UDP") {
        $commonArgs = @("-Protocol:UDP", "-Port:5555", "-BitsPerSecond:320000", "-FrameRate:1000", "-BufferDepth:1", "-StreamLength:100000")
    } else {
        $commonArgs = @("-Pattern:duplex", "-Buffer:$BufferSize", "-RateLimit:$rateLimit", "-RateLimitPeriod:$rateLimitPeriod")
    }

    if ($Role -eq "Server") {
        &"$BinDir\ctsTraffic.exe" -Listen:$Target $commonArgs
    } else {
        &"$BinDir\ctsTraffic.exe" -Target:$Target $commonArgs -Connections:1 -ConsoleVerbosity:1 -StatusUpdate:10
    }
}

[Int64] $lastPingTickCount = (Get-Date).Ticks
[Double] $lastTCPSend = 0
[Double] $lastTCPRecv = 0
[Double] $lastUDP = 0
[Int] $udpInitialBlackout = 0

function Get-CtsTrafficDelta([Double] $Timestamp, [Double] $NewValue) {
    return ($NewValue - $Timestamp) * 1000
}

<#
    Cts Traffic will always output a bunch of garbage to the
    console we don't care about. This function "scrolls" past
    it so it's not parsed.
#>
function Wait-CtsClientJob($Job) {
    for ($i = 0; $i -lt 20000; $i++) {
        foreach ($line in $($Job | Receive-Job)) {
            if ($line -like " TimeSlice*") {
                #Write-Debug "Wait-CtsClientJob : $i iterations."
                return
            }
        }
    }
    throw "Wait-CtsClientJob : Timed out"
}

try {
    # Start ctsTraffic servers
    $serverJobs = @()
    $serverJobs += Invoke-Command -ScriptBlock $ctsTrafficCmd -ArgumentList $BinDir, $Target, "TCP", "Server" `
                                  -AsJob -ComputerName $Target -Credential $Credential
    $serverJobs += Invoke-Command -ScriptBlock $ctsTrafficCmd -ArgumentList $BinDir, $Target, "UDP", "Server" `
                                  -AsJob -ComputerName $Target -Credential $Credential

    # Start clients
    $ctsTCPJob = Start-Job $ctsTrafficCmd -ArgumentList $BinDir, $Target, "TCP", "Client"
    $ctsUDPJob = Start-Job $ctsTrafficCmd -ArgumentList $BinDir, $Target, "UDP", "Client"
    $pingJob = Start-Job -ScriptBlock $pingCmd -ArgumentList $Target

    Wait-CtsClientJob $ctsTCPJob
    Wait-CtsClientJob $ctsUDPJob

    Write-Host "Monitoring... Ctrl+C to stop."
    while ($true) {
        Receive-Job $pingJob | foreach {
            #Write-Debug $_
            $tickCount, $response = $_ -split ","

            if ($response -like "Reply from*") {
                $deltaMS = ([Int64]$tickCount / 10000) - ($lastPingTickCount / 10000)
                if ($deltaMS -gt $BlackoutThreshold) {
                    Write-Output "ICMP Blackout: $deltaMS ms"
                }

                $lastPingTickCount = $tickCount
            }
        }

        # Parse TCP output
        Receive-Job $ctsTCPJob | foreach {
            #Write-Debug $_
            $null, $timestamp, $sendBps, $recvBps, $null = $_ -split "\s+"

            if ($timestamp -eq "TimeSlice") {
                continue
            }

            if (($sendBps -as [Int]) -gt 0) {
                $delta = Get-CtsTrafficDelta $lastTCPSend $timestamp
                if ($delta -gt $BlackoutThreshold) {
                    Write-Output "TCP Send Blackout: $delta ms"
                }
                $lastTCPSend = $timestamp
            }

            if (($recvBps -as [Int]) -gt 0) {
                $delta = Get-CtsTrafficDelta $lastTCPRecv $timestamp
                if ($delta -gt $BlackoutThreshold) {
                    Write-Output "TCP Recv Blackout: $delta ms"
                }
                $lastTCPRecv = $timestamp
            }
        }
    
        # Parse UDP output
        Receive-Job $ctsUDPJob | foreach {
            #Write-Debug $_
            $null, $timestamp, $bitsPerSecond, $null = $_ -split "\s+"

            if ($timestamp -eq "TimeSlice") {
                continue
            }

            if (($bitsPerSecond -as [Int]) -gt 0) {
                if ($udpInitialBlackout -gt 0) {
                    Write-Output "UDP Recv Blackout: $($udpInitialBlackout + ([Double]$timestamp * 1000)) ms"
                    $udpInitialBlackout = 0
                }
                $lastUDP = $timestamp
            } elseif ($udpInitialBlackout -eq 0) {
                $delta = Get-CtsTrafficDelta $lastUDP $timestamp
                if ($delta -gt $BlackoutThreshold) {

                    # CTS Traffic won't restablish the existing UDP
                    # connection, so we need to restart the client.
                    $restartTime = Measure-Command {
                        $ctsUDPJob | Stop-Job | Remove-Job
                        $ctsUDPJob = Start-Job $ctsTrafficCmd -ArgumentList $BinDir, $Target, "UDP", "Client"
                        Wait-CtsClientJob $ctsUDPJob
                    }

                    #Write-Debug "Restart time = $($restartTime.TotalMilliseconds)"

                    $udpInitialBlackout = $delta + $restartTime.TotalMilliseconds
                }
            }
        }
    } # while ($true)
} catch {
    $_
} finally {
    Write-Host "Stopping background tasks..."
    $serverJobs | foreach {$_ | Stop-Job | Remove-Job}

    $ctsTCPJob | Stop-Job | Remove-Job
    $ctsUDPJob | Stop-Job | Remove-Job
    $pingJob | Stop-Job | Remove-Job
}