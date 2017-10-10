# Kubernetes On-Premises Deployment From Scratch -- Start to Finish #
This guide will walk you through deploying *Kubernetes 1.8* on a Linux master and join two Windows nodes to it without a cloud provider.

A few prerequisite definitions and requirements for networking:

  - The **external network** is the physical network across which nodes communicate. This exists regardless of whether or not you follow this guide.
  - The **cluster subnet** is a (<a href="#allow-routing">routable</a>) virtual network that must be a /16. Each _node_ will grab a /24 from the subnet to use for its pods.
  - The **service subnet** is a hardcoded 11.0/16 network that is translated into cluster space by `kube-proxy` running on the node.

**Note**: The guide will assume a local working directory of `~/kube` for the Kubernetes setup. If you choose a different directory, just replace any references to that path.

## Building the Binaries ##
We will begin with a Linux master node on a recent Ubuntu-like distro and a Windows worker node on RS3+; all of these are assumed to be VMs.

First, install all of the pre-requisites on the master:

    $ sudo apt-get install git build-essential docker.io

### Building Kubernetes ###
We will need to build the `kubelet` and `kubeproxy` binaries for Windows from scratch _cross-compiling from Linux_, so let's [set up a Go environment](https://golang.org/doc/install#install) for that, first. This guide assumes Go 1.9 and has not been tested with anything else. With your Go environment ready (don't forget to set your `$GOPATH`!), we can build the Windows binaries:

_You may run into problems with various "permission denied" errors when building these binaries. This is a bug in the Kubernetes build process for Windows, which uses binaries that exist, but are size-zero, and thus don't have executable permissions on them. The solution, unfortunately, is to run `chmod +x _output/bin/*` after every time (~4 times) you hit the error._

```bash
$ K8SREPO="github.com/madhanrm/kubernetes"
$ go get -d $K8SREPO
# Note: the above command may spit out a warning about "no Go files in...", but
#       it can be safely ignored!
$ cd $GOPATH/src/$K8SREPO
$ git checkout cniwindows
$ make clean && make WHAT=cmd/kubelet
$ export KUBE_BUILD_PLATFORMS=windows/amd64
$ make WHAT=cmd/kubelet
$ cp _output/local/bin/windows/amd64/kubelet.exe ~/kube/
$ git checkout winkernelproxy 
$ make WHAT=cmd/kube-proxy
$ cp /_output/local/bin/windows/amd64/kube-proxy.exe ~/kube/
$ unset KUBE_BUILD_PLATFORMS
```

Done! Now, we also need the actual Linux Kubernetes binaries for v1.8. You can pull these from [the Kubernetes mainline](https://github.com/kubernetes/kubernetes/releases/tag/v1.8.0-rc.1), or build them from source as above, except using `K8SREPO=k8s.io/kubernetes` and the `release-1.8` branch. Copy these to `~/kube/bin` (note the extra `/bin` compared to the above path; we actual need to use these during master configuration, rather than just copying them to the Windows node). The v1.8 Windows binary `kubectl.exe` is included in the `windows/` directory of this repo, but you can also build it here (setting `KUBE_BUILD_PLATFORMS=windows/amd64` and `WHAT=cmd/kubectl` as above).

### Install CNI Plugins ###
We also need to install the basic CNI plugin binaries so that networking works. Download them from [here](https://github.com/containernetworking/plugins/releases) and copy them to `/opt/cni/bin/`.

## Prepare the Master ##
Copy the entire directory from [this repository](https://github.com/Microsoft/SDN/tree/master/Kubernetes/linux), which contains a lot of the setup scripts and Kubernetes files that are essential to this process. Check them all out to `~/kube/` and make the scripts executable. This entire directory will be getting mounted for a lot of the docker containers in future steps, so keep its structure the same as outlined in the guide. 

We'll be creating the service cluster on the virtual subnet 11.0/16. This isn't configurable, so if you want to tweak this, it'll require manual modification.

### Certificates ###
First, prepare the certificates that will be used for nodes to communicate in the cluster. Create a `certs/` directory, then move & run `generate-certs.sh` passing **your** external IP as its (only) parameter -- this is likely whatever the IP address of your `eth0` interface is. You can acquire this through `ifconfig` or through:

    $ ip addr show dev eth0

if you already know the interface name. Then:

    ~/kube $ mkdir certs && cd certs
    ~/kube/certs $ mv ../generate-certs.sh .
    ~/kube/certs $ ./generate-certs.sh 10.123.45.67   # example! replace

### Allow Routing ###
_This step may be optional, depending on whether or not you've configured your intended cluster subnet to be routable already_.

Windows nodes will each grab a /24 from the cluster CIDR, so it's 192.168.0.0/16, the first Windows node will use 192.168.0.1/24 for its pods. Pass the first two octets of your clister CIDR to generate the routes:

    ~/kube $ generate-routes.sh 192.168

### Prepare Manifests & Addons ###
In the `manifest` folder, run the Python script, passing your master IP and the _full_ cluster CIDR:

    $ python2 generate.py 10.123.45.67 192.168.0.0/16

This will generate a set of YAML files. You should [re]move the Python script so that K8s doesn't mistake it for a manifest and cause problems.

### Configure & Run Kubernetes ###
Run the script `configure-kubectl.sh` passing your external IP again. This will create a configuration in `~/.kube/config` containing all of the certificate data and other parameters:

    ~/kube $ ./configure-kubectl.sh 10.123.45.67

Run the script `start-kubelet.sh`. You may need to run it with `sudo`. Then, in another shell, watch your working directory (`~/kube`) until the folder `kubelet/` appears. Immediately copy the Kubernetes configuration file to it:

    ~/kube $ sudo cp ~/.kube/config kubelet/

**TODO**: Why is this necessary? Shouldn't this be done automatically by one of the containers?

In another terminal session, run the Kubeproxy script, passing your cluster CIDR (you may also need to run this one with `sudo`):

    ~/kube $ ./kubeproxy.sh 192.168

After a few minutes, you should see the following system state:

  - Under `docker ps`, you should see worker and pod containers mirroring the configs in `manifest/` and in `addons/`.
  - A call to `~/kube/bin/kubectl cluster-info` should show info for the Kubernetes master API server, plus the DNS and heapster addons.
  - A new interface `cbr0` under `ifconfig`, with your chosen cluster CIDR.

## Join a Windows Node ##
Like for Linux, we need an assortment of scripts to prepare things for us. They can be found [here](https://github.com/Microsoft/SDN/tree/master/Kubernetes/windows). Place these in a new folder, `C:\k\`. We also need to copy the .exe binaries we compiled earlier (which we placed in `~/kube/`), as well as the Kubectl config file (from `~/.kube/config`), into this folder. This can be done with something like [WinSCP](https://winscp.net/eng/download.php) or [pscp](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html).

### Build Docker Image ###
We need to build the docker image for the Kubernetes infrastructure. Navigate
to `C:\k\` and run:

    C:\k> docker pull microsoft/windowsservercore-insider:latest
    C:\k> docker tag [SHA from previous cmd] microsoft/windowsservercore:latest
    C:\k> docker build -t kubletwin/pause .

### Join to Cluster ###
In two PowerShell windows, simply run:

    PS> ./start-kubelet.ps1 -ClusterCidr [Full cluster CIDR]
    PS> ./start-kubeproxy.ps1

(in that order). You should be able to see the Windows node when running `./bin/kubectl get nodes` on the Linux master, shortly!

Now, if your cluster CIDR isn't routable, just run this in PowerShell:

    C:\k> AddRoutes.ps1 -MasterIp [Linux Master]
