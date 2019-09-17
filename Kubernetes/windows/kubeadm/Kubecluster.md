How to join a Windows node to a Linux Master using KubeCluster.ps1
==================================================================

Min. Windows Operating System Version : 1809 (Tested).

## Cluster Configuration
```
    {
        "Cri" : {
            "Name" : "<RunTime:dockerd/containerd>",  # Containerd is work in progress
            "Images" : {
                "Nanoserver" : "<NanoserverImageNameWithTag>",
                "ServerCore" : "ServerCodeImageNameWithTag"
            }
        },
        "Cni" : {
            "Name" : "<flannel/kubenet>",   # Kubenet is work in progress
            "Source" : [{ 
                "Name" : "flanneld",
                "Url" : "https://github.com/coreos/flannel/releases/download/v0.11.0/flanneld.exe"
                }
            ],
            "Plugin" : {
                "Name": "<vxlan/bridge>"
            },
            "InterfaceName" : "Ethernet"
        },
        "Kubernetes" : {
            "Release" : "1.14.0",
            "Master" : {
                "IpAddress" : "<NameOrIpOfMaster>",
                "Username" : "<UserNameOfUseronMaster>"
            }
        },
        "Install" : {
            "Destination" : "<InstallDirectory>"
        }
    }
```

## Install Pre-Requisite 
    This option would do the following.

    a. This step would **generate** a SSH key for the windows node and asks the user to add it to the master manually
    b. This step would **install** containers role. [If containers role was already installed, nothing is done here]
    c. A prompt to **restart** the computer, if required (Required when Containers feature is installed.)

    Optionally you can also run this script on a machine, which has containers role, docker and docker images installed. In that case, this option would help generate ssh keys for the windows node.

    d. Usage
    ```
        cd  $env:HOMEDRIVE\$env:HOMEPATH
        wget  https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/kubeadm/KubeCluster.ps1 -o KubeCluster.ps1

        .\KubeCluster.ps1 -InstallPrerequisite -ConfigFile .\KubeCluster.json
    ```
        <The machine might need to be rebooted, if containers role was installed. If not, you can say no>

## Join node to Master
    This option would do the following
    
    a. Install CRI (docker), if not already present
    b. Install Kubernetes binaries from the specified Release param
    c. Downloads the kube config from the master. If no auth is set, it would prompt for the password
    d. Install & Start Kubelet service.
    e. Install CNI & Configurations. Networking Options  -NetworkPlugin vxlan/bridge, -Cni flannel
    f. Install & Start FlannelD service
    g. Install & Start KubeProxy Service.
    _Note: For service installation, a stub service executable is generated & hooked up with Windows SCM._

    cd  $env:HOMEDRIVE\$env:HOMEPATH

### Flannel VxLan
    ```
   	wget  https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/kubeadm/Kubeclustervxlan.json -o kubecluster.json
    # Modify the required params
	.\KubeCluster.ps1 -join -ConfigFile .\KubeCluster.json
    ```
### Flannel Bridge
    # Or input the file directly to the script to deploy the configuration in json
    ```
	.\KubeCluster.ps1 -join -ConfigFile  https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/kubeadm/Kubeclusterbridge.json

    ```
## Reset the node
    This option would undo whatever join did to the node & removes the node from the Kubernetes cluster.
    ```
    
    .\KubeCluster.ps1 -reset -ConfigFile .\KubeCluster.json
    ```

## Sample Output
```
    PS C:\Users\azureuser> wget  https://raw.githubusercontent.com/madhanrm/SDN/kubeadm1/Kubernetes/windows/kubeadm/Kubeclustervxlan.json -o kubecluster.json
PS C:\Users\azureuser> powershell .\KubeCluster.ps1 -InstallPrerequisite -ConfigFile kubecluster.json


    Directory: C:\kubeadm


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2019  10:58 PM                logs
VERBOSE: Using the provider 'NuGet' for searching packages.
VERBOSE: Using the provider 'PowerShellGet' for searching packages.
VERBOSE: Total package yield:'0' for the specified package '7Zip4PowerShell'.
VERBOSE: The -Repository parameter was not specified.  PowerShellGet will use all of the registered repositories.
VERBOSE: Getting the provider object for the PackageManagement Provider 'NuGet'.
VERBOSE: The specified Location is 'https://www.powershellgallery.com/api/v2' and PackageManagementProvider is 'NuGet'.
VERBOSE: Searching repository 'https://www.powershellgallery.com/api/v2/FindPackagesById()?id='7Zip4PowerShell'' for ''.
VERBOSE: Total package yield:'1' for the specified package '7Zip4PowerShell'.
VERBOSE: Performing the operation "Install Package" on target "Package '7Zip4Powershell' version '1.9.0' from 'PSGallery'.".
VERBOSE: The installation scope is specified to be 'CurrentUser'.
VERBOSE: The specified module will be installed in 'C:\Users\azureuser\Documents\WindowsPowerShell\Modules'.
VERBOSE: The specified Location is 'NuGet' and PackageManagementProvider is 'NuGet'.
VERBOSE: Downloading module '7Zip4Powershell' with version '1.9.0' from the repository 'https://www.powershellgallery.com/api/v2'.
VERBOSE: Searching repository 'https://www.powershellgallery.com/api/v2/FindPackagesById()?id='7Zip4Powershell'' for ''.
VERBOSE: InstallPackage' - name='7Zip4Powershell', version='1.9.0',destination='C:\Users\azureuser\AppData\Local\Temp\2\684891628'
VERBOSE: DownloadPackage' - name='7Zip4Powershell', version='1.9.0',destination='C:\Users\azureuser\AppData\Local\Temp\2\684891628\7Zip4Powershell\7Zip4Powershell.nupkg',
uri='https://www.powershellgallery.com/api/v2/package/7Zip4Powershell/1.9.0'
VERBOSE: Downloading 'https://www.powershellgallery.com/api/v2/package/7Zip4Powershell/1.9.0'.
VERBOSE: Completed downloading 'https://www.powershellgallery.com/api/v2/package/7Zip4Powershell/1.9.0'.
VERBOSE: Completed downloading '7Zip4Powershell'.
VERBOSE: Hash for package '7Zip4Powershell' does not match hash provided from the server.
VERBOSE: InstallPackageLocal' - name='7Zip4Powershell', version='1.9.0',destination='C:\Users\azureuser\AppData\Local\Temp\2\684891628'
VERBOSE: Catalog file '7Zip4Powershell.cat' is not found in the contents of the module '7Zip4Powershell' being installed.
VERBOSE: Module '7Zip4Powershell' was installed successfully to path 'C:\Users\azureuser\Documents\WindowsPowerShell\Modules\7Zip4Powershell\1.9.0'.

FastPackageReference : NuGet|7Zip4Powershell|1.9.0|https://www.powershellgallery.com/api/v2|Module
ProviderName         : PowerShellGet
Source               : PSGallery
Status               : Installed
SearchKey            : 7Zip4Powershell
FullPath             :
PackageFilename      : 7Zip4Powershell
FromTrustedSource    : False
Summary              : Powershell module for creating and extracting 7-Zip archives
SwidTags             : {7Zip4Powershell}
CanonicalId          : powershellget:7Zip4Powershell/1.9.0#PSGallery
Metadata             : {summary,versionDownloadCount,ItemType,copyright,PackageManagementProvider,CompanyName,SourceName,tags,created,description,published,developmentDependency,NormalizedVersion,down
                       loadCount,GUID,lastUpdated,Authors,updated,installeddate,isLatestVersion,PowerShellVersion,IsPrerelease,isAbsoluteLatestVersion,packageSize,InstalledLocation,FileList,requireLic
                       enseAcceptance}
SwidTagText          : <?xml version="1.0" encoding="utf-16" standalone="yes"?>
                       <SoftwareIdentity
                         name="7Zip4Powershell"
                         version="1.9.0"
                         versionScheme="MultiPartNumeric" xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd">
                         <Meta
                           summary="Powershell module for creating and extracting 7-Zip archives"
                           versionDownloadCount="117200"
                           ItemType="Module"
                           copyright="2013-2018 Thomas Freudenberg"
                           PackageManagementProvider="NuGet"
                           CompanyName="N/A"
                           SourceName="PSGallery"
                           tags="powershell 7zip 7-zip zip archive extract compress PSModule PSCmdlet_Expand-7Zip PSCommand_Expand-7Zip PSCmdlet_Compress-7Zip PSCommand_Compress-7Zip
                       PSCmdlet_Get-7Zip PSCommand_Get-7Zip PSCmdlet_Get-7ZipInformation PSCommand_Get-7ZipInformation PSIncludes_Cmdlet"
                           created="8/15/2018 5:39:39 PM +00:00"
                           description="Powershell module for creating and extracting 7-Zip archives"
                           published="8/15/2018 5:39:39 PM +00:00"
                           developmentDependency="False"
                           NormalizedVersion="1.9.0"
                           downloadCount="178912"
                           GUID="bd4390dc-a8ad-4bce-8d69-f53ccf8e4163"
                           lastUpdated="4/16/2019 10:56:32 PM +00:00"
                           Authors="Thomas Freudenberg"
                           updated="2019-04-16T22:56:32Z"
                           installeddate="4/16/2019 10:58:21 PM"
                           isLatestVersion="True"
                           PowerShellVersion="2.0"
                           IsPrerelease="false"
                           isAbsoluteLatestVersion="True"
                           packageSize="1411309"
                           InstalledLocation="C:\Users\azureuser\Documents\WindowsPowerShell\Modules\7Zip4Powershell\1.9.0"
                           FileList="7Zip4PowerShell.nuspec|7z.dll|7z64.dll|7Zip4PowerShell.dll|7Zip4PowerShell.psd1|JetBrains.Annotations.dll|SevenZipSharp.dll"
                           requireLicenseAcceptance="False" />
                         <Entity
                           name="Thomas Freudenberg"
                           regId="Thomas Freudenberg"
                           role="author" />
                         <Entity
                           name="thoemmi"
                           regId="thoemmi"
                           role="owner" />
                         <Link
                           href="https://github.com/thoemmi/7Zip4Powershell/blob/master/LICENSE"
                           rel="license" />
                         <Link
                           href="https://github.com/thoemmi/7Zip4Powershell"
                           rel="project" />
                         <Link
                           href="https://raw.githubusercontent.com/thoemmi/7Zip4Powershell/master/Assets/7zip4powershell.png"
                           rel="icon" />
                       </SoftwareIdentity>
Dependencies         : {}
IsCorpus             :
Name                 : 7Zip4Powershell
Version              : 1.9.0
VersionScheme        : MultiPartNumeric
TagVersion           :
TagId                :
IsPatch              :
IsSupplemental       :
AppliesToMedia       :
Meta                 : {{summary,versionDownloadCount,ItemType,copyright,PackageManagementProvider,CompanyName,SourceName,tags,created,description,published,developmentDependency,NormalizedVersion,dow
                       nloadCount,GUID,lastUpdated,Authors,updated,installeddate,isLatestVersion,PowerShellVersion,IsPrerelease,isAbsoluteLatestVersion,packageSize,InstalledLocation,FileList,requireLi
                       censeAcceptance}}
Links                : {license:https://github.com/thoemmi/7Zip4Powershell/blob/master/LICENSE, project:https://github.com/thoemmi/7Zip4Powershell,
                       icon:https://raw.githubusercontent.com/thoemmi/7Zip4Powershell/master/Assets/7zip4powershell.png}
Entities             : {Thomas Freudenberg, thoemmi}
Payload              :
Evidence             :
Culture              :
Attributes           : {name,version,versionScheme}

########################################
User Input
Destination       : C:\kubeadm
Master            : kubemaster
InterfaceName     : Ethernet
Cri               : dockerd
Cni               : flannel
NetworkPlugin     : vxlan
Release           : 1.14.0
########################################
Do you wish to generate a SSH Key & Add it to the Linux Master [Y/n] - Default [Y] : : Y
Generating public/private rsa key pair.
Enter file in which to save the key (C:\Users\azureuser/.ssh/id_rsa):
Created directory 'C:\Users\azureuser/.ssh'.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in C:\Users\azureuser/.ssh/id_rsa.
Your public key has been saved in C:\Users\azureuser/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:IOZ9HYiXhlsSUL0eLQIjHJI15dG3cG6uL0Q/hWM8QP8 azureuser@k8swinworker2
The key's randomart image is:
+---[RSA 2048]----+
|.++o+=+.         |
|..ooo.+=+o       |
|   .+o=BB=.      |
|   o ooB&oo.     |
|    ..oBS*E      |
|      ..=        |
|     . . .       |
|      o          |
|       o.        |
+----[SHA256]-----+
Execute the below cmd in Linux Master(kubemaster) to add this Windows Node's public key to its authorized keys
touch ~/.ssh/authorized_keys
echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMJiFDR1DOZcJsiD4CCq7bOfsPUAIkf776FNekG+Cs2FhiVbpS316zJ8RsE6jCuCUl/Mu30Ax+6XVT0vz30XzQDO4lgIi8ITGEjGg3+y9Q8a0eFzjWFGx8oYmXNHqHX+QwQpKsfu34byXjRxyLCK45QGXVtAp3e9JzoQIVyuU+ELsxTV8+ihw9eGnKUhjLQhE6eTNfLiLSNW3jpUYC3UDOPSNe7MI/DIEF0XERGAgOBneTtLBbTMBvulD/RGCwPVSC/3A0GTdnQ6wUH0Po2v4jf+7bD8hYiSe1pIRlW3FuzZNjGCAIDGGpaaD2uA5dQn7yhjFAgEH5pa76sRvOVCLT azureuser@k8swinworker2 >> ~/.ssh/authorized_keys
Continue to Reboot the host [Y/n] - Default [Y] : : n


PS C:\Users\azureuser> ls


    Directory: C:\Users\azureuser


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2019  10:58 PM                .ssh
d-r---        4/16/2019  10:55 PM                3D Objects
d-r---        4/16/2019  10:55 PM                Contacts
d-r---        4/16/2019  10:55 PM                Desktop
d-r---        4/16/2019  10:55 PM                Documents
d-r---        4/16/2019  10:55 PM                Downloads
d-r---        4/16/2019  10:55 PM                Favorites
d-r---        4/16/2019  10:55 PM                Links
d-r---        4/16/2019  10:55 PM                Music
d-r---        4/16/2019  10:55 PM                Pictures
d-r---        4/16/2019  10:55 PM                Saved Games
d-r---        4/16/2019  10:55 PM                Searches
d-r---        4/16/2019  10:55 PM                Videos
-a----        4/16/2019  10:58 PM            889 kubecluster.json
-a----        4/16/2019  10:56 PM           8912 kubecluster.ps1


PS C:\Users\azureuser> notepad .\kubecluster.json
PS C:\Users\azureuser> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : shuzinpbx0mejpynpzhpeo0rwe.cx.internal.cloudapp.net
   Link-local IPv6 Address . . . . . : fe80::e848:b82e:a09c:b687%7
   IPv4 Address. . . . . . . . . . . : 10.0.0.6
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.0.1

Ethernet adapter vEthernet (nat):

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::34b5:b7e:ceb6:5800%13
   IPv4 Address. . . . . . . . . . . : 172.28.96.1
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . :
PS C:\Users\azureuser> docker images
REPOSITORY                             TAG                 IMAGE ID            CREATED             SIZE
mcr.microsoft.com/windows/servercore   ltsc2019            954d1507112f        7 days ago          4.43GB
mcr.microsoft.com/windows/nanoserver   1809                e9bbec97e222        7 days ago          250MB
```

```
PS C:\Users\azureuser> powershell .\KubeCluster.ps1 -join -ConfigFile kubecluster.json


    Directory: C:\Users\azureuser\kubeadm


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2019  11:00 PM                logs
########################################
User Input
Destination       : C:\Users\azureuser\kubeadm
Master            : k8smaster1
InterfaceName     : Ethernet 2
Cri               : dockerd
Cni               : flannel
NetworkPlugin     : vxlan
Release           : 1.14.0
########################################
Downloading Kubeconfig from k8smaster1:~/.kube/config to C:\Users\azureuser\kubeadm\config
The authenticity of host 'k8smaster1 (10.0.0.4)' can't be established.
ECDSA key fingerprint is SHA256:N2Tc3N9osjDfSC9m9kbCQ9xbozY1C9Ql/dehrbtKT5w.
Are you sure you want to continue connecting (yes/no)?
Warning: Permanently added 'k8smaster1,10.0.0.4' (ECDSA) to the list of known hosts.
config                                                                                                                                                                 100% 5444     5.3KB/s   00:00
protocol error: lost connection
No infrastructure container image found. Building kubeletwin/pause image
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/windows/Dockerfile] => [C:\Users\azureuser\kubeadm\Dockerfile]
Sending build context to Docker daemon  12.29kB
Step 1/2 : FROM mcr.microsoft.com/windows/nanoserver
 ---> e9bbec97e222
Step 2/2 : CMD cmd /c ping -t localhost
 ---> Running in 0250229c4622
Removing intermediate container 0250229c4622
 ---> 9c19b01f8a62
Successfully built 9c19b01f8a62
Successfully tagged kubeletwin/pause:latest
Downloaded [https://dl.k8s.io/v1.14.0/kubernetes-node-windows-amd64.tar.gz] => [C:\Users\azureuser\AppData\Local\Temp\2\tmp655C.tar.gz]
Trying to connect to the Kubernetes master
####################################
Able to connect to the Master
Discovered the following
Cluster CIDR    : 10.244.0.0/16
Service CIDR    : 10.96.0.0/12
DNS ServiceIp   : 10.96.0.10
####################################
Installing Kubelet Service


    Directory: C:\Users\azureuser\kubeadm\logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2019  11:00 PM                kubelet
Create a SCMService Binary for [Kubelet] [C:\Users\azureuser\kubeadm\kubernetes\node\bin\kubelet.exe --hostname-override=k8swinworker2 --v=6 --pod-infra-container-image=kubeletwin/pause --resolv-conf="" --allow-privileged=true --enable-debugging-handlers --cluster-dns=10.96.0.10 --cluster-domain=cluster.local --kubeconfig=C:\Users\azureuser\kubeadm\config --hairpin-mode=promiscuous-bridge --image-pull-progress-deadline=20m --cgroups-per-qos=false --log-dir=C:\Users\azureuser\kubeadm\logs\kubelet --logtostderr=false --enforce-node-allocatable="" --network-plugin=cni --cni-bin-dir=C:\Users\azureuser\kubeadm\cni --cni-conf-dir=C:\Users\azureuser\kubeadm\cni\config --node-ip=10.0.0.6 --feature-gates=] => [C:\Users\azureuser\kubeadm\KubeletSvc.exe]

Status      : Stopped
Name        : Kubelet
DisplayName : Kubelet

    ++++++++++++++++++++++++++++++++
    Successfully created the service
    ++++++++++++++++++++++++++++++++
    Service [Kubelet]
    Cmdline [C:\Users\azureuser\kubeadm\KubeletSvc.exe]
    Env     []
    Log     [C:\Users\azureuser\kubeadm\logs\kubelet\kubeletsvc.log]
    ++++++++++++++++++++++++++++++++


    Directory: C:\Users\azureuser\kubeadm


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2019  11:00 PM                cni
Downloading Flannel binaries
Downloaded [https://github.com/coreos/flannel/releases/download/v0.11.0/flanneld.exe] => [C:\Users\azureuser\kubeadm\flanneld.exe]
Downloading CNI binaries for overlay to C:\Users\azureuser\kubeadm\cni


    Directory: C:\Users\azureuser\kubeadm\cni


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2019  11:00 PM                config
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/overlay/cni/config/cni.conf] => [C:\Users\azureuser\kubeadm\cni\config\cni.conf]
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/l2bridge/cni/flannel.exe] => [C:\Users\azureuser\kubeadm\cni\flannel.exe]
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/l2bridge/cni/host-local.exe] => [C:\Users\azureuser\kubeadm\cni\host-local.exe]
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/overlay/cni/win-overlay.exe] => [C:\Users\azureuser\kubeadm\cni\win-overlay.exe]
Installing FlannelD Service


    Directory: C:\Users\azureuser\kubeadm\logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2019  11:00 PM                flanneld
Downloaded [https://github.com/madhanrm/SDN/raw/kubeadm/Kubernetes/flannel/overlay/net-conf.json] => [C:\Users\azureuser\kubeadm\net-conf.json]


    Directory: C:\etc


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2019  11:00 PM                kube-flannel
Create a SCMService Binary for [FlannelD] [C:\Users\azureuser\kubeadm\flanneld.exe --kubeconfig-file=C:\Users\azureuser\kubeadm\config --iface=10.0.0.6 --ip-masq=1 --kube-subnet-mgr=1] => [C:\Users\azureuser\kubeadm\FlannelDSvc.exe]

Status      : Stopped
Name        : FlannelD
DisplayName : FlannelD

    ++++++++++++++++++++++++++++++++
    Successfully created the service
    ++++++++++++++++++++++++++++++++
    Service [FlannelD]
    Cmdline [C:\Users\azureuser\kubeadm\FlannelDSvc.exe]
    Env     [{
    "NODE_NAME":  "k8swinworker2"
}]
    Log     [C:\Users\azureuser\kubeadm\logs\flanneld\flanneldsvc.log]
    ++++++++++++++++++++++++++++++++
Generated CNI Config [{
    "cniVersion":  "0.2.0",
    "name":  "vxlan0",
    "type":  "flannel",
    "delegate":  {
                     "type":  "win-overlay",
                     "dns":  {
                                 "Nameservers":  [
                                                     "10.96.0.10"
                                                 ],
                                 "Search":  [
                                                "svc.cluster.local"
                                            ]
                             },
                     "Policies":  [
                                      {
                                          "Name":  "EndpointPolicy",
                                          "Value":  {
                                                        "Type":  "OutBoundNAT",
                                                        "ExceptionList":  [
                                                                              "10.244.0.0/16",
                                                                              "10.96.0.0/12"
                                                                          ]
                                                    }
                                      },
                                      {
                                          "Name":  "EndpointPolicy",
                                          "Value":  {
                                                        "Type":  "ROUTE",
                                                        "DestinationPrefix":  "10.96.0.0/12",
                                                        "NeedEncap":  true
                                                    }
                                      }
                                  ]
                 }
}]
Generated net-conf Config [{
    "Network":  "10.244.0.0/16",
    "Backend":  {
                    "name":  "vxlan0",
                    "type":  "vxlan"
                }
}]

Caption                 :
Description             : Overlay network traffic UDP
ElementName             : Overlay Traffic 4789 UDP
InstanceID              : OverlayTraffic4789UDP
CommonName              :
PolicyKeywords          :
Enabled                 : True
PolicyDecisionStrategy  : 2
PolicyRoles             :
ConditionListType       : 3
CreationClassName       : MSFT|FW|FirewallRule|OverlayTraffic4789UDP
ExecutionStrategy       : 2
Mandatory               :
PolicyRuleName          :
Priority                :
RuleUsage               :
SequencedActions        : 3
SystemCreationClassName :
SystemName              :
Action                  : Allow
Direction               : Inbound
DisplayGroup            :
DisplayName             : Overlay Traffic 4789 UDP
EdgeTraversalPolicy     : Block
EnforcementStatus       : NotApplicable
LocalOnlyMapping        : False
LooseSourceMapping      : False
Owner                   :
Platforms               : {}
PolicyStoreSource       : PersistentStore
PolicyStoreSourceType   : Local
PrimaryStatus           : OK
Profiles                : 0
RuleGroup               :
Status                  : The rule was parsed successfully from the store. (65536)
StatusCode              : 65536
PSComputerName          :
Name                    : OverlayTraffic4789UDP
ID                      : OverlayTraffic4789UDP
Group                   :
Profile                 : Any
Platform                : {}
LSM                     : False


ActivityId             : 19C8DEBE-0BA9-4C37-A3FF-DE1FBF03B288
AdditionalParams       :
CurrentEndpointCount   : 0
DNSServerCompartment   : 3
DrMacAddress           : 00-15-5D-7B-82-55
Extensions             : {@{Id=E7C3B2F0-F3C5-48DF-AF2B-10FED6D72E7A; IsEnabled=False; Name=Microsoft Windows Filtering Platform}, @{Id=E9B59CFA-2BE1-4B21-828F-B6FBDBDDC017; IsEnabled=True;
                         Name=Microsoft Azure VFP Switch Extension}, @{Id=EA24CD6C-D17A-4348-9190-09F0D5BE83DD; IsEnabled=True; Name=Microsoft NDIS Capture}}
Flags                  : 0
Health                 : @{LastErrorCode=0; LastUpdateTime=131999292562686835}
ID                     : 6F7E13A2-8ADE-48EE-844E-AC0B0AFF235D
IPv6                   : False
LayeredOn              : 241F09EF-FB6A-44F6-9D54-DDB8BD487CE3
MacPools               : {@{EndMacAddress=00-15-5D-1B-FF-FF; StartMacAddress=00-15-5D-1B-F0-00}}
ManagementIP           : 10.0.0.6
MaxConcurrentEndpoints : 0
Name                   : External
NetworkAdapterName     : Ethernet 2
Policies               : {}
Resources              : @{AdditionalParams=; AllocationOrder=1; Allocators=System.Object[]; Health=; ID=19C8DEBE-0BA9-4C37-A3FF-DE1FBF03B288; PortOperationTime=0; State=1; SwitchOperationTime=0;
                         VfpOperationTime=0; parentId=28656732-D066-4A42-BCFC-45F998A035A2}
State                  : 1
Subnets                : {@{AdditionalParams=; AddressPrefix=192.168.255.0/30; GatewayAddress=192.168.255.1; Health=; ID=A1320335-EB6A-4247-8FA4-47471041D2F5; ObjectType=5; Policies=System.Object[];
                         State=0}}
TotalEndpoints         : 0
Type                   : overlay
Version                : 38654705666

Waiting for the Network (vxlan0) to be created by flanneld


    Directory: C:\Users\azureuser\kubeadm\logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2019  11:01 PM                kube-proxy
Installing Kubeproxy Service
Create a SCMService Binary for [Kubeproxy] [C:\Users\azureuser\kubeadm\kubernetes\node\bin\kube-proxy.exe --hostname-override=k8swinworker2 --v=4 --proxy-mode=kernelspace --kubeconfig=C:\Users\azureuser\kubeadm\config --network-name=vxlan0 --cluster-cidr=10.244.0.0/16 --log-dir=C:\Users\azureuser\kubeadm\logs\kube-proxy --logtostderr=false --feature-gates=WinOverlay=true --source-vip=10.244.1.2] => [C:\Users\azureuser\kubeadm\KubeproxySvc.exe]

Status      : Stopped
Name        : Kubeproxy
DisplayName : Kubeproxy

    ++++++++++++++++++++++++++++++++
    Successfully created the service
    ++++++++++++++++++++++++++++++++
    Service [Kubeproxy]
    Cmdline [C:\Users\azureuser\kubeadm\KubeproxySvc.exe]
    Env     []
    Log     [C:\Users\azureuser\kubeadm\logs\kube-proxy\kubproxysvc.log]
    ++++++++++++++++++++++++++++++++
NAME            STATUS   ROLES    AGE     VERSION
k8smaster1      Ready    master   3m14s   v1.14.1
k8swinworker2   Ready    <none>   22s     v1.14.0
Node k8swinworker2 successfully joined the cluster


PS C:\Users\azureuser>
```
Check if all policies are programmed in hns
```
PS C:\Users\azureuser> hnsdiag list all
Networks:
Name             ID
nat              B5083512-BE1D-4326-B58F-56CA5154E8D5
External         6F7E13A2-8ADE-48EE-844E-AC0B0AFF235D
vxlan0           705B6B4D-E2F2-421A-B31B-E3C5E8831944

Endpoints:
Name             ID                                   Virtual Network Name
Ethernet         11796e63-07b3-4199-91d5-9bc25108fb41 vxlan0
Ethernet         07f382ab-8884-40ba-8adf-efe4c92e8608 vxlan0
Ethernet         99f4e4e7-0ff0-4cf7-9301-3bd1628beaf9 vxlan0
Ethernet         3e0c5e8d-346a-49ca-a6a3-11785d351970 vxlan0
Ethernet         fc0bbb8f-52a6-486f-bff8-10ab92859006 vxlan0
Ethernet         ba06178e-11e9-4ba3-931d-7c2989b51dd7 vxlan0

Namespaces:
ID                                   | Endpoint IDs

LoadBalancers:
ID                                   | Virtual IPs      | Direct IP IDs
326f84d7-35ec-4355-a60a-e82e2b05ec24 |  10.96.0.1       | ba06178e-11e9-4ba3-931d-7c2989b51dd7
af826f8b-9f78-41ea-bc9e-6e433f8784df |  10.96.0.10      | fc0bbb8f-52a6-486f-bff8-10ab92859006 07f382ab-8884-40ba-8adf-efe4c92e8608
8c35026b-3ee6-47f1-b254-ae0b5ba7144c |  10.96.0.10      | fc0bbb8f-52a6-486f-bff8-10ab92859006 07f382ab-8884-40ba-8adf-efe4c92e8608
fac498e1-f37f-4bc4-b30c-6bfdec2dc58e |  10.96.0.10      | fc0bbb8f-52a6-486f-bff8-10ab92859006 07f382ab-8884-40ba-8adf-efe4c92e8608
```

## Open Issues ([WIP])
1. Restart of VM/Host is not fully tested. If you would like to restart, do reset and join again
2. Service dependency is not fully sorted out. Ie Restarting Kubelet, KubeProxy and FlannelD is different orders manually may result in non-working cluster. 
3. Kubeproxy has to wait for the network creation internally. It also has to wait, if the network goes away, until it comes back
4. FlannelD should create the network in non-persistent mode. Ie on host restart, the network would go away and would appear back when flannelD service is started.
