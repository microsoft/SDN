# Using SDNExpress

## Prerequisites:

- Physical switch and router configuration according to the best practices outlined in the [Planning a SDN infrastructure](https://docs.microsoft.com/en-us/windows-server/networking/sdn/plan/plan-a-software-defined-network-infrastructure) topic.

- A VHDX containing Windows Server 2016 or 2019, Datacenter Edition.  It is recommended that you start with a VHDX that contains the latest updates at the time of deployment.  The version of the Operating System in your deployment VHDX must match the version used by the Hyper-V hosts.  If you have an ISO you can generate a VHDX using [Convert-WindowsImage](https://gallery.technet.microsoft.com/scriptcenter/Convert-WindowsImageps1-0fe23a8f) and the following commands after mounting the ISO to a drive letter:
    ```
    $wimpath = "d:\sources\install.wim"
    $vhdpath = "c:\temp\WindowsServerDatacenter.vhdx"
    $Edition = 4   # 4 = Full Desktop, 3 = Server Core
    
    import-module ".\convert-windowsimage.ps1"
    
    Convert-WindowsImage -SourcePath $wimpath -Edition $Edition -VHDPath $vhdpath -SizeBytes 500GB -DiskLayout UEFI
    ```

## Usage:

Interactive:
```
.\SDNExpress.ps1
```

Using a config file:
```
.\SDNExpress.ps1 -ConfigurationDataFile .\myconfig.psd1 -verbose
```

Using a configuration object:
```
.\SDNExpress.ps1 -ConfigurationData $MyConfig -verbose
```
As a module:
```
Import-Module .\SDNExpressModule.psm1
```


This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
