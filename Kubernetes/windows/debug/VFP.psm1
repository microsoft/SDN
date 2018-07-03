##############################################################################
#.SYNOPSIS
# Gets the VFP port associated with the given mac address
#
#.DESCRIPTION
# Gets the VFP port associated with the given mac address.
# Throws if the mac address can not be found on any VFP port.
##############################################################################
function parseVfpPort([string] $data)
{
    if ([string]::IsNullOrEmpty($data)) {throw "Invalid Port data String"}


    $vfpPort = @{
    }

    $m = ($data | out-string | Select-String -Pattern '(?sm)(.*?): (.*?)\r\n' -AllMatches).Matches
    $m[0..7] | foreach {
        $vfpPort += @{
            $_.Groups[1].Value.Trim() = $_.Groups[2].Value.Trim();
        }
    }

    $m[9..13] | foreach {
        $vfpPort += @{
            $_.Groups[1].Value.Trim() = $_.Groups[2].Value.Trim();
        }
    }

    return  New-Object -TypeName PSObject -Property $vfpPort
}

function parseKeyValue([string] $kvpStringData)
{
    if ([string]::IsNullOrEmpty($kvpStringData)) {throw "Invalid kvp String"}
    $kvp = @{}
    
    ($kvpStringData | Select-String -Pattern '(.*?) : (.*)\r\n' -AllMatches).Matches | foreach {
        if ($_){
            $kvp += @{
                $_.Groups[1].Value.Trim() = $_.Groups[2].Value.Trim();
            }
        }
    }

    return $kvp
}

function Get-VfpPorts()
{
    Param(
        [ValidateNotNullorEmpty()]
        [string]$SwitchName = $(throw "Please provide a switch name."),
        [parameter(Mandatory=$false)][string]$MacAddress
        )
    $vfpPorts = @()
    (vfpctrl.exe /list-vmswitch-port | out-string | Select-String -Pattern '(?sm)(^Port name.*?: .*?\r\n\r\n)' -AllMatches).Matches | foreach {
        $vfpPorts += (parseVfpPort $_.Value)
    }

    if ($MacAddress)
    {
        return $vfpPorts | ? 'MAC address' -EQ $MacAddress
    }

    return $vfpPorts
}

function parseVfpLayer([string] $layerStringData)
{
    if ([string]::IsNullOrEmpty($layerStringData)) {throw "Invalid Layer String"}

    $layer = @{
        Name = ($layerStringData | Select-String -Pattern '(LAYER) : (.*)\r\n').Matches.Groups[2].Value;
        Data = @{};
        Groups = @();
    }

    $layerData = ($layerStringData | Select-String -Pattern '(?sm)(^    .*\n)').Matches.Groups[0].Value
    ($layerData | Select-String -Pattern '(?sm)^    (.*?) : (.*?)$' -AllMatches).Matches | foreach {
        $layer.Data += @{
            $_.Groups[1].Value.Trim() = $_.Groups[2].Value.Trim();
        }
    }


    return New-Object -TypeName PSObject -Property $layer;
}

function Get-VfpLayers()
{
    Param(
        [ValidateNotNullorEmpty()]
        [Guid]$Port = $(throw "Please provide a value for Port.")
    )

    $layers = @();

    ((vfpctrl.exe /list-layer /port $Port) | out-String | Select-String -Pattern '(?sm)(^LAYER : .*?\r\n\r\n?$)' -AllMatches).Matches | foreach {
        if ($_) {
            $layer = (parseVfpLayer($_.Value))
            $layer.Groups = @(); $layer.Groups += (Get-VfpGroups -Port $Port -Layer $layer.Name)
            $layers += $layer
        }
    }
   
    
    return $layers;
}

function parseVfpGroup([string] $groupStringData)
{
    if ([string]::IsNullOrEmpty($groupStringData)) {throw "Invalid Group String"}

    <# 
        GROUP : VNET_GROUP_PA_ROUTE_IPV4_OUT
          Friendly name : VNET_GROUP_PA_ROUTE_IPV4_OUT
          Priority : 200
          Direction : OUT
          Type : IPv4
            Conditions:
                <none>
          Match type : Priority-based match
    #>

    $group = @{
        Name = ($groupStringData | Select-String -Pattern '(GROUP) : (.*)\r\n').Matches.Groups[2].Value;
        Data = @{};
        Conditions = @{}
        Rules = @();
    }

    ($groupStringData | Select-String -Pattern '      (.*?) : (.*)\r\n' -AllMatches).Matches | foreach {
        if ($_) {
            $group.Data += @{
                $_.Groups[1].Value.Trim() = $_.Groups[2].Value.Trim();
            }
        }
    }

    # Check for Condition
    if (($groupStringData | Select-String -Pattern '(?smi)        Conditions:\r\n.*?<none>\r\n' -AllMatches).Matches.Count -eq 1)
    {
    } else {
        # Parse Condition
        ($groupStringData | Select-String '(?smi)        (Conditions:\r\n)(            .*?)\r\n' -AllMatches).Matches | foreach {
            if ($_) {
                $rule.Conditions += (parseKeyValue $_.Groups[2].Value)
            }
        }
    }


    return New-Object -TypeName PSObject -Property $group;
}

function Get-VfpGroups()
{
    Param(
        [ValidateNotNullorEmpty()]
        [Guid]$Port = $(throw "Please provide a value for Port."),
        [string]$Layer = $(throw "Please provide a value for Layer.")
    )
    
    $groups = @();
    (vfpctrl /list-group /port $Port /layer $Layer | out-string | Select-String '(?sm)(^  GROUP : .*?)\r\n\r\n' -AllMatches).Matches | foreach {
        if ($_) {
            $group = (parseVfpGroup($_.Value))
            $group.Rules = @(); $group.Rules += (Get-VfpRules -Port $Port -Layer $Layer -Group $group.Name)
            $groups += $group
        }
    }

    return $groups
}


#
# FIXME : Parse Conditions and Modify correctly.
#
function parseVfpRule([string] $ruleStringData)
{
    if ([string]::IsNullOrEmpty($ruleStringData)) {throw "Invalid rule String"}

    <# 
        RULE :
                   Friendly name : PA_ROUTE
                   Priority : 45535
                   Flags : 1 terminating
                   Type : paroute
                   Conditions:
                       <none>
                   Flow TTL: 0
                   Rule Data:
                   VLAN ID: 0
                   Using default compartment
                   Cache pruning threshold: 10
                   Cache pruning timeout: 30 seconds
                   Using interface constraint with interface index: 11
                   FlagsEx : 0
    #>

    $rule = @{
        Conditions = @{};
        Modify = @{};
    }

    ($ruleStringData | Select-String -Pattern '      (.*?) : (.*)\r\n' -AllMatches).Matches | foreach {
        if ($_) {
            $rule += @{
                $_.Groups[1].Value.Trim() = $_.Groups[2].Value.Trim();
            }
        }
    }

    # FixMe : Condition is not parsed correctly
    # Check for Condition
    if (($ruleStringData | Select-String -Pattern '(?smi)        Conditions:\r\n.*?<none>\r\n' -AllMatches).Matches.Count -eq 1)
    {
    } else {
        # Parse Condition
        ($ruleStringData | Select-String '(?smi)        (Conditions:\r\n)(            .*?)\r\n' -AllMatches).Matches | foreach {
            if ($_) {
                $rule.Conditions += (parseKeyValue $_.Groups[2].Value)
            }
        }
    }

    ($ruleStringData | Select-String '(?smi)        (Modify:\r\n)(            .*?)\r\n' -AllMatches).Matches | foreach {
        if ($_) {
            $rule.Modify += (parseKeyValue $_.Groups[2].Value)
        }
    }

    return New-Object -TypeName PSObject -Property $rule;
}

############s##################################################################
#.SYNOPSIS
# Returns all the rules for the specified port
#
#.DESCRIPTION
# Given a port, layer and group returns all the rules for the port 
##############################################################################
function Get-VfpRules()
{
    Param(
        [ValidateNotNullorEmpty()]
        [Guid]$Port = $(throw "Please provide a value for Port."),
        [string]$Layer = $(throw "Please provide a value for Layer."),
        [string]$Group = $(throw "Please provide a value for Group.")
    )

    $rules = @()
    (vfpctrl.exe /list-rule /port $Port /layer $Layer /group $Group | out-string | Select-String '(?sm)(RULE : .*?)\r\n\r\n' -AllMatches).Matches | foreach {
        if ($_) {
            $rules += (parseVfpRule $_.Value);
        }
    }
    return  $rules
}


function Get-VfpRules_HnsPolicy()
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [Object[]] $InputObjects
    )
    begin {$Objects = @(); $retObjects = @()}
    process {$Objects += $InputObjects; }
    end {
        $Objects | foreach {  
            $retObjects += (Get-VfpRules_HnsPolicyId $_.Id)
        }
        return $retObjects;
    }
}

function Get-VfpRules_HnsPolicyId()
{
    Param(
        [ValidateNotNullorEmpty()]
        [Guid]$PolicyListId = $(throw "Please provide a Id for Policy List.")
    )
    throw "TBD"
}


############s##################################################################
#.SYNOPSIS
# Returns all the rules for the Hns Endpoint
#
#.DESCRIPTION
# Given an Endpoint Object, fetch all the corresponding Vfp Rules
##############################################################################

function Get-VfpRules_HnsEndpoint()
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [Object[]] $InputObjects
    )
    begin {$Objects = @(); $retObjects = @()}
    process {$Objects += $InputObjects; }
    end {
        $Objects | foreach {  
            $retObjects += (Get-VfpRules_HnsEndpointId $_.Id)
        }
        return $retObjects;
    }
}

function Get-VfpRules_HnsEndpointId()
{
    Param(
        [ValidateNotNullorEmpty()]
        [Guid]$EndpointId = $(throw "Please provide a Id for Endpoint.")
    )

    $ep = (Get-HnsEndpoint $EndpointId)
    $port = Get-VfpPorts -SwitchName $ep.VirtualNetworkName -MacAddress $ep.MacAddress
    
    throw "TBD"

    #return Get-VfpLayers -Port $port.'Port name'
}