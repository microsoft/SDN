# Kubernetes with Windows | Start to Finish #
This guide will walk you through deploying *Kubernetes 1.8* on a Linux master and join two Windows nodes to it without a cloud provider.

**If you have an existing cluster**, skip everything regarding Linux master setup and read [this section](#deploying-on-existing-clusters).


## Assumptions and Prerequisites ##
A few prerequisite definitions and requirements for networking:

  - The **external network** is the physical network across which nodes communicate. This exists regardless of whether or not you follow this guide.
  - The **cluster subnet** is a (<a href="#allow-routing">routable</a>) virtual network that must be a /16. Each _node_ will grab a /24 from the subnet to use for its pods. See [this section](#optional-customize-cluster-cidr) for modifying this value.
  - The **service subnet** is a hardcoded 11.0/16 network that is translated into cluster space by `kube-proxy` running on the node.

It is assumed you will be setting up the following:

  - 1 Linux machine on an Ubuntu-like OS; this will be the single master node.
  - 2 up-to-date Windows Server 2016 machines; these are the worker nodes.
  - Compilation of the Windows binaries can be done on the master, a temporary host via Vagrant, or some other build environment.
  - The cluster subnet is assumed to be 192.168.0.0/16 but could be specified otherwise. Changes to this value are *not covered* but *are noted.* See [this section](#optional-customize-cluster-cidr) for more details.
  - The service subnet is assumed to be 11.0.0.0/16 and is hardcoded throughout the scripts. Changes to this value are *not covered.*

The machines can be VMs (which is assumed throughout the guide) or bare-metal hosts. Both should work identically. 

**Note**: The guide will assume a local working directory of `~/kube` for the Kubernetes setup. If you choose a different directory, just replace any references to that path.

**Note**: As of this writing, the latest 1.8 version of Kubernetes was 1.8.2. You can check this [here](https://github.com/kubernetes/kubernetes/releases) and update all references to `1.8.x` accordingly.


## Preparing the Master ##
First, let's install all of the pre-requisites:

    $ sudo apt-get install curl git build-essential docker.io conntrack

We can pull most of the binaries we need from the official Kubernetes repository, but will need to cross-compile one of the Windows binaries ourselves because it isn't "officially released."

There is a collection of scripts in [this repository](https://github.com/Microsoft/SDN/tree/master/Kubernetes/linux), which will help us with the setup process. Check them all out to `~/kube/` and make the scripts executable. This entire directory will be getting mounted for a lot of the docker containers in future steps, so keep its structure the same as outlined in the guide.

    $ mkdir ~/kube
    $ git clone https://github.com/Microsoft/SDN /tmp/k8s 
    $ mv -R /tmp/k8s/Kubernetes/linux/ ~/kube/


### Installing the Linux Binaries ###
Now, we also need the actual Linux Kubernetes binaries. Download the archive from the [Kubernetes mainline](https://github.com/kubernetes/kubernetes/releases/tag/v1.8.2) and install them like so:

```bash
wget -O kubernetes.tar.gz https://github.com/kubernetes/kubernetes/releases/download/v1.8.2/kubernetes.tar.gz
tar -vxzf kubernetes.tar.gz 
cd kubernetes/cluster 
# follow the prompts from this command:
./get-kube-binaries.sh
cd ../server
tar -vxzf kubernetes-server-linux-amd64.tar.gz 
cd kubernetes/server/bin
cp hyperkube kubectl ~/kube/bin/
```

Add the binaries to your `$PATH`, so that we can run them from everywhere. Note that this only sets the path for your session; add it to your `~/.profile` for a permanent setting.

    $ PATH="$HOME/kube/bin:$PATH"


### Install CNI Plugins ###
Install the basic CNI plugins so that networking works. Download them from [here](https://github.com/containernetworking/plugins/releases) and extract + copy them to `/opt/cni/bin/`. Or, run these commands:

```bash
DOWNLOAD_DIR="${HOME}/kube/cni-plugins"
CNI_BIN="/opt/cni/bin/"
mkdir ${DOWNLOAD_DIR}
cd $DOWNLOAD_DIR
curl -L $(curl -s https://api.github.com/repos/containernetworking/plugins/releases/latest | grep browser_download_url | grep 'amd64.*tgz' | head -n 1 | cut -d '"' -f 4) -o cni-plugins-amd64.tgz
tar -xvzf cni-plugins-amd64.tgz
sudo mkdir -p ${CNI_BIN}
sudo cp -r !(*.tgz) ${CNI_BIN}
ls ${CNI_BIN}
```


### Certificates ###
First, acquire your local IP address, either via `ifconfig` or:

    $ ip addr show dev eth0

if you already know the interface name. Then, set it as an environmental variable, `MASTER_IP`, because we'll be referencing it a lot in this guide. Note that you will need to set this again if you end your session. Now, prepare the certificates that will be used for nodes to communicate in the cluster:

    ~/kube $ MASTER_IP=10.123.45.67   # example! replace
    ~/kube $ cd certs
    ~/kube/certs $ ./generate-certs.sh $MASTER_IP


### Prepare Manifests & Addons ###
In the `manifest` folder, run the Python script, passing your master IP and the _full_ cluster CIDR:

    $ ./generate.py $MASTER_IP 192.168.0.0/16

This will generate a set of YAML files. You should [re]move the Python script so that Kubernetes doesn't mistake it for a manifest; this will cause problems.


### *Optional*: Customize Cluster CIDR ###
It's possible that you don't have a continous /16 open for cluster routing. This requires more effort on your part as the configurator, as you'll have to explicitly specify per-node CIDRs that you have available. First, you will need to modify the `kube-controller-manager.yaml` configuration file that we just generated. Search for this line:

    - "--allocate-node-cidrs=True"

and change it to `=False`. Now, Kubernetes will not automatically assign subnets to new nodes. Read [this section](#optional-customize-windows-node-cidr) to know what to do on the Windows nodes; the same logic applies to the `start-kubelet.sh` script on the master, and any Linux worker node `kubelet` calls.


### Configure & Run Kubernetes ###
Configure Kubernetes with the certificates we generated previously. This will create a configuration at `~/.kube/config`:

    ~/kube $ ./configure-kubectl.sh $MASTER_IP

Finally, we're ready to start `kubelet`, the Kubernetes "client." This script runs indefinitely, so open another shell afterward to keep working:

    ~/kube $ sudo ./start-kubelet.sh

Watch your working directory until the `kubelet` _folder_ appears in it. Immediately copy the Kubernetes configuration file to it:

    ~/kube $ sudo cp ~/.kube/config kubelet/

You may need to restart the `start-kubelet.sh` script after this if it wasn't picked up fast enough.

> This is a quirky workaround because for whatever reason, the API server pod doesn't mount the configuration file like it should.

In yet another terminal session, run the Kubeproxy script, passing your cluster CIDR

    ~/kube $ sudo ./start-kubeproxy.sh 192.168


## Verifying the Master ##
After a few minutes, you should see the following system state:

  - Under `docker ps`, you should see many worker and pod containers.
  - A call to `kubectl cluster-info` should show info for the Kubernetes master API server, plus DNS and Heapster addons.
  - `ifconfig` should show a new interface `cbr0` with your chosen cluster CIDR.


### *Optional*: Allow Routing ###
_This step may be optional, depending on whether or not you've configured your intended cluster subnet to be routable already_.

Windows nodes will each grab a /24 from the cluster CIDR as offered by the master (unless you're configuring [custom per-node CIDRs](#optional-customize-cluster-cidr)). For example, the first Windows node could use 192.168.1.0/24 for its pods, the second could use 192.168.2.0/24, and so on.

In order for pods to be able to communicate, you'll need to generate static routes between them. Run the `generate-routes.sh` script:

    $ sudo ./generate-routes.sh 192.168

As you add more Windows nodes, you will need to run commands similar to that at the end of the script, except with `$CLUSTER.3.0`, etc. The gateway for Windows nodes will always be a `.2`. You will need to run analogous commands [on the Windows side](#join-to-cluster) later.


## Deploying On Existing Clusters ##
This section applies to people who want to add nodes to an existing Linux cluster that they've painstakingly set up. Whether set up manually, or via `kubeadm`, the only thing that you need from the Linux master is the _certificate configuration file_.

If you used `kubeadm`, this would probably be at `/etc/kubernetes/admin.conf`. If you deployed manually, this may be at `~/.kube/config`. Wherever it is, just drop a copy at `C:\k\config` on the Windows node and things should work.

Of course, you will still need to [build the Windows binaries](#building-kubernetes-windows-binaries) on a Linux box.


## Building Kubernetes' Windows Binaries ##
We will need to build the `kubelet` and `kubeproxy` binaries for Windows from scratch by _cross-compiling from Linux_. There are multiple ways to do this:

  - Build them [locally](#build-locally).
  - Generate the binaries using [Vagrant](#build-with-vagrant).
  - Leverage the [standard containerized build scripts](https://github.com/kubernetes/kubernetes/tree/master/build#key-scripts) in the Kubernetes project. For this, follow the steps for [building locally](#build-locally) up to the `make` steps, then use the linked instructions.

**Note**: If you run into "permission denied" errors, these can be avoided by building the Linux `kubelet` first, per the note in [acs-engine](https://github.com/Azure/acs-engine/blob/master/scripts/build-windows-k8s.sh#L176):

> Due to what appears to be a bug in the Kubernetes Windows build system, one has to first build a Linux binary to generate `_output/bin/deepcopy-gen`. Building to Windows w/o doing this will generate an empty `deepcopy-gen`.

Additionally, you will need to download the `kubectl.exe` binary. The [release notes](https://github.com/kubernetes/kubernetes/releases/tag/v1.8.2) have links in the `CHANGELOG-1.8.md` file. Copy these to a new directory, `~/kube-win`. We'll need to transfer them to the Windows node later:

```bash
mkdir ~/kube-win
wget -O kubernetes-windows.tar.gz https://dl.k8s.io/v1.8.2/kubernetes-client-windows-amd64.tar.gz
tar -vxzf kubernetes-windows.tar.gz 
cp kubernetes/client/bin/kubectl.exe ~/kube-win/
```


#### Build Locally ####
Set up a [Go environment](https://golang.org/doc/install#tarball); don't forget to set your `$GOPATH`! Then, run these commands to build:

```bash
$ KUBEREPO="k8s.io/kubernetes"
$ go get -d $KUBEREPO
# Note: the above command may spit out a message about 
#       "no Go files in...", but it can be safely ignored!
$ cd $GOPATH/src/$KUBEREPO
# if you want the "bleeding edge" Kubernetes, run 
# `git checkout release-1.8` here.
$ git checkout tags/v1.8.2
$ make clean && make WHAT=cmd/kubelet

# necessary to add a bug-fix not yet upstream'd
$ git add remote patch https://github.com/madhanrm/kubernetes
$ git fetch patch
$ git cherry-pick cba7ee2a4ee64bd4aafafa403d583310a49853fd

# finally, we can build the binary
$ KUBE_BUILD_PLATFORMS=windows/amd64 make WHAT=cmd/kube-proxy
$ cp /_output/local/bin/windows/amd64/kube-proxy.exe ~/kube-win/
```

Until [this PR](https://github.com/kubernetes/kubernetes/pull/51063) is merged into the Kubernetes mainline, you will need to build `kubelet.exe` from the fork:

```bash
$ KUBEREPO="github.com/madhanrm/kubernetes"
$ go get -d $KUBEREPO
$ cd $GOPATH/src/$KUBEREPO
$ git checkout cniwindows
$ make clean && make WHAT=cmd/kubelet
$ KUBE_BUILD_PLATFORMS=windows/amd64 make WHAT=cmd/kubelet
$ cp _output/local/bin/windows/amd64/kubelet.exe ~/kube-win
```

Done! Skip ahead to [preparing the Windows node](#prepare-a-windows-node).


#### Build with Vagrant ####
Prepare a [Vagrant VM](linux/vagrant/readme.md), and execute these commands inside it:

```bash
DIST_DIR="${HOME}/kube/"
SRC1_DIR="${HOME}/src/k8s-fork/"
SRC2_DIR="${HOME}/src/k8s-main/"
mkdir ${DIST_DIR}
mkdir -p "${SRC1_DIR}"
mkdir -p "${SRC2_DIR}"

git clone https://github.com/madhanrm/kubernetes.git ${SRC1_DIR}
git clone https://github.com/kubernetes/kubernetes.git ${SRC2_DIR}

cd ${SRC1_DIR}
git checkout cniwindows
KUBE_BUILD_PLATFORMS=linux/amd64   build/run.sh make WHAT=cmd/kubelet
KUBE_BUILD_PLATFORMS=windows/amd64 build/run.sh make WHAT=cmd/kubelet 
cp _output/dockerized/bin/windows/amd64/kubelet.exe ${DIST_DIR}

cd ${SRC2_DIR}
git checkout tags/v1.8.2
git add remote patch https://github.com/madhanrm/kubernetes
git fetch patch
git cherry-pick cba7ee2a4ee64bd4aafafa403d583310a49853fd
KUBE_BUILD_PLATFORMS=windows/amd64 build/run.sh make WHAT=cmd/kube-proxy 
cp _output/dockerized/bin/windows/amd64/kube-proxy.exe ${DIST_DIR}
ls ${DIST_DIR}
```
Done!


## Prepare a Windows Node ##
We need a baseline of configuration on Windows nodes. This can be in a hypervisor or otherwise, but the instances require an external network IP (accessible by other hosts, not necessarily the public Internet).

In an *elevated* PowerShell prompt, run:

```powershell
Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
Install-Package -Name docker -ProviderName DockerMsftProvider
Restart-Computer -Force
```


## Join a Windows Node ##
Like with Linux, we have an assortment of scripts to prepare things for us. They can be found [here](https://github.com/Microsoft/SDN/tree/master/Kubernetes/windows). Place these in a new folder, `C:\k\`. We also need to copy the .exe binaries we compiled earlier (from `~/kube-win`), as well as the Kubernetes certificate configuration file (from `~/.kube/config`), into this folder. This can be done with something like [WinSCP](https://winscp.net/eng/download.php) or [pscp](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html).


### Build Docker Image ###
We need to build the docker image for the Kubernetes infrastructure. Navigate to `C:\k\` and run:

    C:\k> docker pull microsoft/windowsservercore:1709
    C:\k> docker tag [SHA from previous cmd] microsoft/windowsservercore:latest
    C:\k> docker build -t kubeletwin/pause .


### Join to Cluster ###
In two separate PowerShell windows, run these scripts (in this order!):

    PS> ./start-kubelet.ps1 -ClusterCidr [Full cluster CIDR]
    PS> ./start-kubeproxy.ps1

You should be able to see the Windows node when running `kubectl get nodes` on the Linux master, shortly!


#### *Optional*: Enable Pod Routing ####
Analogous to the [Linux section](#optional-allow-routing), we need to create static routes between the pods. Just run this in PowerShell (after finding out the necessary parameters under `ifconfig` and `ipconfig`, respectively):

    C:\k> AddRoutes.ps1 -MasterIp [Linux Master IP] -Gateway [Windows Gateway]

As you add more nodes, you will need to edit this script on every node to add the new routes, as well as on the [Linux master](#optional-allow-routing).


#### *Optional*: Customize Windows Node CIDR ####
Modify the last of `start-kubelet.ps1` script to contain this parameter:

    --pod-cidr=[pod CIDR for this node]
