# This script is for testing purposes; The below registration is being added to the manifest.

param(
  [switch]$remove,  # remove the plugin
  [parameter(Mandatory=$false)] [String]$addr,
  [parameter(Mandatory=$false)] [int]$port,
  [parameter(Mandatory=$false)] [String]$path,
  [parameter(Mandatory=$false)] [String]$format
)

$agentpath = $path    # gets overwritten later, but still keep it user-friendly

if(!$remove)
{
  function enable-privilege {
    param(
      ## The privilege to adjust. This set is taken from
      ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
      [ValidateSet(
       "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
       "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
       "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
       "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
       "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
       "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
       "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
       "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
       "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
       "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
       "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
      $Privilege,
      ## The process on which to adjust the privilege. Defaults to the current process.
      $ProcessId = $pid,
      ## Switch to disable the privilege, rather than enable it.
      [Switch] $Disable
    )

     ## Taken from P/Invoke.NET with minor adjustments.
     $definition = @'
     using System;
     using System.Runtime.InteropServices;

     public class AdjPriv
     {
      [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
      internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
       ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

      [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
      internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
      [DllImport("advapi32.dll", SetLastError = true)]
      internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
      [StructLayout(LayoutKind.Sequential, Pack = 1)]
      internal struct TokPriv1Luid
      {
       public int Count;
       public long Luid;
       public int Attr;
      }

      internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
      internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
      internal const int TOKEN_QUERY = 0x00000008;
      internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
      public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
      {
       bool retVal;
       TokPriv1Luid tp;
       IntPtr hproc = new IntPtr(processHandle);
       IntPtr htok = IntPtr.Zero;
       retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
       tp.Count = 1;
       tp.Luid = 0;
       if(disable)
       {
        tp.Attr = SE_PRIVILEGE_DISABLED;
       }
       else
       {
        tp.Attr = SE_PRIVILEGE_ENABLED;
       }
       retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
       retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
       return retVal;
      }
     }
'@

     $processHandle = (Get-Process -id $ProcessId).Handle
     $type = Add-Type $definition -PassThru
     $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
    }
    $RegPath="SYSTEM\CurrentControlSet\Services\hns\Parameters"
    enable-privilege SeTakeOwnershipPrivilege
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($RegPath,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)
    # You must get a blank acl for the key b/c you do not currently have access
    $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
    $me =  [System.Security.Principal.NTAccount]"$env:userdomain\$env:username"
    $acl.SetOwner($me)
    $key.SetAccessControl($acl)

    # After you have set owner you need to get the acl with the perms so you can modify it.
    $acl = $key.GetAccessControl()
    $person = [System.Security.Principal.NTAccount]"Administrators"
    $access = [System.Security.AccessControl.RegistryRights]"FullControl"
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"

    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $person,$access,$inheritance,$propagation,$type
    )
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
    $key.Close()
}

$clsid_plugin = "D5AAF7C4-1B3E-4b49-9CF9-9263FAB9DC6D"
$path = "HKLM:\system\CurrentControlSet\services\hns\Parameters"

$pluginpath = "$path\Plugins\$clsid_plugin"
$node = new-item $pluginpath -force;
$null = new-itemproperty -path $pluginpath -name "Priority" -value 1000;
$null = new-itemproperty -path $pluginpath -name "NetworkRequests" -value 31;
$null = new-itemproperty -path $pluginpath -name "EndpointRequests" -value 31;
$null = new-itemproperty -path $pluginpath -name "ServiceRequests" -value 7;

# If the user specified a particular set of configuration parameters, install..
if ($addr -and $port -and $format -and $agentpath)
{
  $VALID_FORMATS = "xml","json"
  $format = $format.ToLower();
  $isValidFormat = $false;

  foreach ($fmt in $VALID_FORMATS)
  {
    if ($format -eq $fmt)
    {
      $isValidFormat = $true;
      break;
    }
  }

  if (!$isValidFormat)
  {
    Write-Host -ForegroundColor red -NoNewline "Invalid format! ($format) ... "
    Write-Host -ForegroundColor red "Must be one of [ ($VALID_FORMATS -join ', ') ]"
  }
  else
  {
    echo "Installing configuration: request=${addr}:${port}/${agentpath}, format=${format}"
    $null = New-ItemProperty -Path $pluginpath -name "AgentIPAddress" -value $addr
    $null = New-ItemProperty -Path $pluginpath -name "AgentFormat" -value $format
    $null = New-ItemProperty -Path $pluginpath -name "AgentPort" -value $port
    $null = New-ItemProperty -Path $pluginpath -name "AgentPath" -value $agentpath
  }
}

$data = @(
[psobject]@{ Path="HKLM:Software\Classes\CLSID\{$clsid_plugin}";
             Values = @{ "(default)" = "Private Cloud HNS Plugin"; }; };
[psobject]@{ Path="HKLM:Software\Classes\CLSID\{$clsid_plugin}\InprocServer32";
             Values = @{"(default)" = "c:\windows\system32\PrivateCloudHNSPlugin.dll"; "ThreadingModel"="Both";}; };
);

if($remove)
{
  $keys = @($data.Path);
  [array]::Reverse($keys);
  foreach($key in $keys)
  {
    write-host $key
    remove-item $key -confirm:$false -erroraction silentlycontinue;
  }
}
else
{
  foreach($r in $data)
  {
    $path = $r.Path;
    write-host $path
    $node = new-item $path -force;
    foreach($name in $r.Values.Keys)
    {
      $propertyvalue = $r.Values[$name];
      Write-host "  $name => $propertyvalue";
      $null = new-itemproperty -path $path -name $name -value $propertyvalue;
    }
  }
}

Restart-Service hns
