# Container Networking Issues

> If you face DNS or networking issues with containers, **the best solution** is to ensure you are running the _**most recent Windows release**_. We worked  very hard to iron out container networking issues in Windows Server, version 1803 and Windows 10 April 2018 Update, so we encourage you to update and benefit from the smoother experience provided by the newest releases.

## Windows Predecessors (Pre-1803)
Please see the table below for a curated history of workaround steps concerning container networking issues plaguing prior Windows releases.

| Symptom | Workaround  | Impacted Builds |
|---------|-------------|-----------------|
| 15 minute DNS blackout period | Install KB 4074588 (released February 13, 2018) | <= Windows 1703 |
| Port collision or connection failures when WinNAT tries to reserve ports | Install KB 4074588 (released February 13, 2018) | <= Windows 1703 |
 | Kubernetes service VIP access fails | **(Fixed in Windows Server, version 1709 only at this time)** <ul><li>Install Optional Update 4C (released April 19th)</li><li>Install KB4089848 (released March 22, 2018)</li><li>Configure a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) to always keep one normal (non-privileged) pod running</li></ul> | <= Windows Server, version 1709 |
| When workload container is unstable and crashes, the network namespace is cleaned up | Redeploy any affected service(s) | <= Windows Server, version 1709 |
|When Kubernetes node on which container is running becomes unavailable, DNS queries may fail resulting in a "negative cache entry" | Run the following _inside_ affected containers: <ul><li> `New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name MaxCacheTtl -Value 0 -Type DWord`</li><li>`New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name MaxNegativeCacheTtl -Value 0 -Type DWord`</li><li>`Restart-Service dnscache` </li></ul><br> If this still doesn't resolve the problem, then you may be forced to disable DNS caching completely as a **LAST RESORT**: <ul><li>`Set-Service dnscache -StartupType disabled`</li><li>`Stop-Service dnscache`</li></ul> | <= Windows Server, version 1709 |
| On restart of a Kubernetes node, container outbound connectivity is lost | Run the following on the container host: <ul><li>`Stop-service kubeproxy`</li><li>`Stop-service kubelet`</li><li>`iwr https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/hns.psm1 -useb -OutFile hns.psm1` and [import-module](https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/Import-Module)</li><li>`Get-HnsPolicyList \| Remove-HnsPolicyList`</li><li>`Get-HnsNetworks \| ? Name -eq <network-mode (eg: l2bridge)> \| Remove-HnsNetwork`</li><li>`Start-sevice kubelet`</li><li>`Start-service kubeproxy`</li> | = Windows Server, version 1709 |
| On restart of a Kubernetes node, Docker takes a long time to start  | Install KB 4093105. If the issue still occurs, run the following on the container host:<ul><li>Delete the HNS.data file located at `C:\Programdata\Microsoft\Windows\HNS\hns.data`</li><li>Restart HNS Service</li></ul> | = Windows Server, version 1709 |

## Current Windows Release (Windows Server, version 1803 and Windows 10 April 2018 Update)

Emerging technology such as containers isn't always perfect and despite our best efforts to weed them out, ~~[insects rule the world](https://news.nationalgeographic.com/2016/11/bugs-insects-ants-evolution-beetles/)~~ bugs may still creep up on us. _However_, thankfully there is an active community that you can _directly_ reach out to via [Slack](https://slack.com/). If you are facing networking-related issues **on the newest Windows release**, do the following:

 ## 1. Ensure your feature is supported on Windows
 Some features  _just don't seem to work_. Often, this is because the desired functionality is simply a platform limitation that hasn't been filed yet! Here are the most popular requests:
 * Balancing network traffic across Kubernetes pods and services via DNSRR
 * Accessing Kubernetes service VIPs from Windows nodes
 * Encrypted container communication via IPsec.
 * HTTP proxy support for containers.  A preliminary PR for this can be tracked [here](https://github.com/Microsoft/hcsshim/pull/163).
 * Attaching endpoints to running Hyper-V containers (hot-add).

Please make sure your encountered issue is not due to one of the platform gaps above. To keep tabs on our current platform roadmap, feel free to check out the [Windows K8s Roadmap](https://trello.com/b/rjTqrwjl/windows-k8s-roadmap).

## 2. Run the [CollectLogs.ps1](https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/debug/collectlogs.ps1) PowerShell script
The following script will compile diagnostics about your host network:
```
iwr https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/debug/collectlogs.ps1 -useb | iex
```

This will create a new directory with a randomly generated name. For example:
```
Logs are available at b4w4dprk.3rw  # <--- zip b4w4dprk.3rw up & share!
```

**(Optional)** If you are unable to run the script, please install the Hyper-V role:
```
dism /Online /Enable-Feature /FeatureName:Microsoft-Hyper-V /All /NoRestart
```

## 3. Get in touch with the Windows container community
Zip this directory _(`b4w4dprk.3rw` above)_ into an archive, and get in touch with the community via the [Kubernetes Slack](https://kubernetes.slack.com/) on channel `#sig-windows`:
  * `@daschott`
  * `@jemesser81`
  * `@madhanrm`
  * `@dineshgovindasamy`