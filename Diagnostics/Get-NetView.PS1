<#
.SYNOPSIS
    Get-NetView has moved to https://github.com/microsoft/Get-NetView

    To install the latest version:

        Install-Module Get-NetView

    To directly download from the new location:

        Invoke-WebRequest "aka.ms/Get-NetView" -OutFile "Get-NetView.ps1"
.DESCRIPTION
    See SYNOPSIS.
.LINK
    https://github.com/microsoft/Get-NetView
#>
Param($OutputDirectory = "", $ExtraCommands = @(), $MaxThreads = 5, [Switch] $SkipAdminCheck = $false)

function Get-NetView {
    [CmdletBinding()]
    Param($OutputDirectory, $ExtraCommands, $MaxThreads, [Switch] $SkipAdminCheck)

    $msg = "This script has moved to https://github.com/microsoft/Get-NetView`n" +
           " `n" +
           "To install the latest version:`n" +
           " `n" +
           "    Install-Module Get-NetView`n" +
           "`n `n" +
           "To directly download from the new location,:`n" +
           "`n `n" +
           "    Invoke-WebRequest `"aka.ms/Get-NetView`" -OutFile `"Get-NetView.ps1`"`n" +
           " "

    Write-Error $msg

} Get-NetView @PSBoundParameters
