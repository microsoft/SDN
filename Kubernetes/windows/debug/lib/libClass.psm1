# Data structure for ETW providers.
# This implementation requires the use of the ETW GUID. 
# Everything else is optional with default values for level and keywords.

using namespace System.Collections.Generic

class Provider {
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
    ) {
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
    ) {
        $this.Name              = ""
        $this.GUID              = $GUID
        $this.Level             = $level
        $this.MatchAnyKeyword   = $MatchAnyKeyword
    }

    # GUID and level property
    Provider(
        [guid]$GUID,
        [byte]$Level
    ) {
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
    ) {
        $this.Name              = $Name
        $this.GUID              = $GUID
        $this.Level             = $level
        $this.MatchAnyKeyword   = [UInt64]::MaxValue
    }

    # only GUID
    Provider(
        [guid]$GUID
    ) {
        $this.Name              = ""
        $this.GUID              = $GUID
        $this.Level             = [byte]::MaxValue
        $this.MatchAnyKeyword   = [UInt64]::MaxValue
    }

    #endregion Provider()
}