# My Intention is to build a Prerequisite Check.
# It uses a premade Config file and check's it against the actual setup.
# Different variants like running SDN-Express Script from local Hyper-V Host, Inside a (Network Controller) VM or from external OS should be considered.

# Load the Config File
[CmdletBinding(DefaultParameterSetName="NoParameters")]
param(
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationFile")]
    [String] $ConfigurationDataFile=$null,
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationData")]
    [object] $ConfigurationData=$null,
    [Switch] $SkipValidation,
    [Switch] $SkipDeployment,
    [PSCredential] $DomainJoinCredential = $null,
    [PSCredential] $NCCredential = $null,
    [PSCredential] $LocalAdminCredential = $null
    ) 

# Script version, should be matched with the config files
$ScriptVersion = "2.0"

# Decrypt of passwords from config file.
function GetPassword 
{
    param(
        [String] $SecurePasswordText,
        [PSCredential] $Credential,
        [String] $Message,
        [String] $UserName
    )
    if ([String]::IsNullOrEmpty($SecurePasswordText) -and ($Credential -eq $null)) {
        write-sdnexpresslog "No credentials found on command line or in config file.  Prompting."    
        $Credential = get-Credential -Message $Message -UserName $UserName
    }

    if ($Credential -ne $null) {
        write-sdnexpresslog "Using credentials from the command line."    
        return $Credential.GetNetworkCredential().Password
    }

    try {
        write-sdnexpresslog "Using credentials from config file."    
        $securepassword = $SecurePasswordText | convertto-securestring -erroraction Ignore
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    } catch {
        write-sdnexpresslog "Unable to decrpypt credentials in config file.  Could be from a different user or generated on different computer.  Prompting instead."    
        $Credential = get-Credential -Message $Message -UserName $UserName
        if ($credential -eq $null) {
            write-sdnexpresslog "User cancelled credential input.  Exiting."    
            exit
        }
        return $Credential.GetNetworkCredential().Password
    }

}

$DomainJoinPassword = GetPassword $ConfigData.DomainJoinSecurePassword $DomainJoinCredential "Enter credentials for joining VMs to the AD domain." $configdata.DomainJoinUserName
$NCPassword = GetPassword $ConfigData.NCSecurePassword $NCCredential "Enter credentials for the Network Controller to use." $configdata.NCUserName
$LocalAdminPassword = GetPassword $ConfigData.LocalAdminSecurePassword $LocalAdminCredential "Enter the password for the local administrator of newly created VMs.  Username is ignored." "Administrator"

$NCSecurePassword = $NCPassword | convertto-securestring -AsPlainText -Force

$credential = New-Object System.Management.Automation.PsCredential($ConfigData.NCUsername, $NCSecurePassword)

$ManagementSubnetBits = $ConfigData.ManagementSubnet.Split("/")[1]
$PASubnetBits = $ConfigData.PASubnet.Split("/")[1]
$DomainJoinUserNameDomain = $ConfigData.DomainJoinUserName.Split("\")[0]
$DomainJoinUserNameName = $ConfigData.DomainJoinUserName.Split("\")[1]
$LocalAdminDomainUserDomain = $ConfigData.LocalAdminDomainUser.Split("\")[0]
$LocalAdminDomainUserName = $ConfigData.LocalAdminDomainUser.Split("\")[1]

if ($ConfigData.VMProcessorCount -eq $null) {$ConfigData.VMProcessorCount = 8}
if ($ConfigData.VMMemory -eq $null) {$ConfigData.VMMemory = 8GB}

# Variant Run from Hyper-V Host
$WinVersion = Get-CimInstance Win32_OperatingSystem -Property * | select Caption
$WinVariants = "2016","2019"
# check for windows version


If ($WinVersion -notcontain $WinVariants_) {
	write-error "Wrong Version installed. Use only Server 2016 or later."
	return
}


$feature = Get-WindowsFeature "Hyper-V"
if ($feature -eq $null) {
    write-error "SDN Express requires Hyper-V."
	return
}
if (!$feature.Installed) {
    throw "Hyper-V is installed."
}

$feature = Get-Windowsfeature "RSAT-NetworkController"
if ($feature -eq $null) {
    throw "It appears that RSAT-NetworkController isn't installed."
}
if (!$feature.Installed) {
    add-windowsfeature "RSAT-NetworkController"
}

# Check if at least one virtual switch with switchtype external is available.
$VMSwitchAvailable = Get-VMSwitch -SwitchType External

if ($VMSwitchAvailable -eq $null) {
    write-error "No Virtual Switch with Type External is available."
	return
}
