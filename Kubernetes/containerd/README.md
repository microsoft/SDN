# CRI/ContainerD on Windows

## Prerequisites

### ContainerD Binaries
You will need to build the following binaries and copy them to the specified folder
* `containerd.exe`
  * https://github.com/jterry75/cri/tree/windows_port/cmd/containerd
  * `C:\Program Files\containerd`
  * This is a temporary location for CRI/Containerd's Windows port and is currently in the process of being upstreamed
* `ctr.exe`
  * https://github.com/containerd/cri/tree/master/cmd/ctr
  * `C:\Program Files\containerd`
* `containerd-shim-runhcs-v1.exe`
  * https://github.com/containerd/containerd/tree/master/cmd/containerd-shim-runhcs-v1
  * `C:\Program Files\containerd`

You can use the following command to build and place the binaries in the working directory.
Copy `cribuild.sh` to the working directory before running it.
```bash
docker run --rm -v "$PWD":/out -w /out golang:stretch bash cribuild.sh
```

### Windows Features
Windows Server 2019 is required with Hyper-V and Containers installed.
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName "Containers" -All
Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V" -All
```
The node should also be fully updated before continuing.

### Flannel
Flannel should be set up on the cluster with `host-gw` as the backend.

## Setup and Running
Run `.\start.ps1` to setup and run the kubelet and containerd on the local node.
This script will download most dependencies and config files.

```powershell
# Setup and run containerd and kubelet locally
# the config file can be obtained from /etc/kubernetes/admin.conf on the master
.\start.ps1 -ConfigFile my-config.conf

# Skip setup and only run containerd and kubelet
.\start.ps1 -ConfigFile my-config.conf -SkipInstall

# Setup, but not run, containerd and kubelet locally
.\start.ps1 -OnlyInstall
```

Please note that this requires nodes to have L2 connectivity.