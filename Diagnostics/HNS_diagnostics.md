# Container Networking Diagnostics

> If you face DNS or networking issues with containers, **the best solution** is to ensure you are running the _**most recent Windows release**_. We worked  very hard to iron out container networking issues in Windows 1803, so we encourage you to update and benefit from the smoother experience provided by the newest releases.

## Windows Predecessors (Pre-1803)
Please see the table below for a curated history of workaround steps concerning container networking issues plaguing prior Windows releases.

| Symptom | Workaround  | Impacted Builds |
|-------------|-------------|-----------------|---------------|
| 15 minute DNS blackout period | Install KB 4074588 (released February 13, 2018) | <= Windows 1703 |
| Port collision or connection failures when WinNAT tries to reserve ports | Install KB 4074588 (released February 13, 2018) | <= Windows 1703 |
 | Kubernetes service VIP access fails | **(Fixed in Windows 1709 only)** <ul><li>Install Optional Update 4C (released April 19th)</li><li>Install KB4089848 (released March 22, 2018)</li><li>Configure a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) to always keep one normal (non-privileged) pod running</li></ul> | <= Windows 1709 |
| When workload container is unstable and crashes, the network namespace is cleaned up | Redeploy any affected service(s) | <= Windows 1709 |
|When Kubernetes node on which container is running becomes unavailable, DNS queries may fail resulting in a "negative cache entry" | Run the following _inside_ affected containers: <ul><li> `New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name MaxCacheTtl -Value 0 -Type DWord`</li><li>`New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name MaxNegativeCacheTtl -Value 0 -Type DWord`</li><li>`Restart-Service dnscache` </li></ul><br> If this still doesn't resolve the problem, then you may be forced to disable DNS caching completely as a **LAST RESORT**: <ul><li>`Set-Service dnscache -StartupType disabled`</li><li>`Stop-Service dnscache`</li></ul> | <= Windows 1709 |
| On restart of a Kubernetes node, container outbound connectivity is lost | Run the following on the container host: <ul><li>`Stop-service kubeproxy`</li><li>`Stop-service kubelet`</li><li>`iwr https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/hns.psm1 -useb -OutFile hns.psm1` and [import-module](https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/Import-Module)</li><li>`Get-HnsPolicyList | Remove-HnsPolicyList`</li><li>`Get-HnsNetworks | ? Name -eq <network-mode (eg: l2bridge)> | Remove-HnsNetwork`</li><li>`Start-sevice kubelet`</li><li>`Start-service kubeproxy`</li> | = Windows 1709 |

## Current Windows Release (1803)

Emerging technology such as containers isn't always perfect and despite our best efforts to weed them out, ~~[insects rule the world](https://news.nationalgeographic.com/2016/11/bugs-insects-ants-evolution-beetles/)~~ bugs will still creep up -- even in new Windows releases! HOWEVER, the cool thing is that you can reach the product group _directly_ via [Slack](https://slack.com/). Just remember to provide some diagnostics so you can get the most timely help. **If you are facing networking-related issues on the newest Windows release, do the following**:

1.  Run the [CollectLogs.ps1](https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/debug/collectlogs.ps1) PowerShell script to compile diagnostics about your host network:
```
iwr https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/debug/collectlogs.ps1 -useb | iex
```

This will create a new directory with a random name. For example:
```
Logs are available at b4w4dprk.3rw  # <--- zip b4w4dprk.3rw up & share!
```

2. Zip this directory _(`b4w4dprk.3rw` above)_ into an archive, and get in touch with the product group via the [Kubernetes Slack](https://kubernetes.slack.com/) on channel `#<TODO>`:
  *  `@daschott`
  * `@jemesser81`
  * `@madhanrm`
  * `@dineshgovindasamy`