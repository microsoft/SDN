How to deploy a Linux Master using kubecluster.sh
=================================================

This is just a wrapper on top of kubeadm

## Deploy Master (and pre-requisites)
	• Download Ubuntu Server Iso -  
	Start-BitsTransfer http://releases.ubuntu.com/18.10/ubuntu-18.10-live-server-amd64.iso
	• Create a new VM & boot using the Ubuntu Server ISO
	• Install Ubuntu Server [Using default option]
	• From windows powershell or linux shell 
		ssh <userId>@<LinuxIpOrName>
		Wget https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/linux/kubeadm/kubecluster.sh

### Flannel VxLan
	sudo bash kubecluster.sh --init --clustercidr 10.244.0.0/16 --servicecidr 10.96.0.0/12 --cni flannel --networkplugin vxlan --destination $HOME/kubeadm

### Flannel Bridge
	sudo bash kubecluster.sh --init --clustercidr 10.244.0.0/16 --servicecidr 10.96.0.0/12 --cni flannel --networkplugin bridge --destination $HOME/kubeadm

## Reset the node
    This option would undo whatever join did to the node & removes the node from the Kubernetes cluster.
	sudo bash kubecluster.sh --reset --clustercidr 10.244.0.0/16 --servicecidr 10.96.0.0/12 --cni flannel --networkplugin bridge --destination $HOME/kubeadm

## Sample Output

```
madhanm@k8smaster1:~$ wget https://raw.githubusercontent.com/madhanrm/SDN/kubeadm/Kubernetes/linux/kubeadm/kubecluster.sh
--2019-04-16 22:51:59--  https://raw.githubusercontent.com/madhanrm/SDN/kubeadm/Kubernetes/linux/kubeadm/kubecluster.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 151.101.248.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|151.101.248.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8005 (7.8K) [text/plain]
Saving to: ‘kubecluster.sh’

kubecluster.sh                100%[=================================================>]   7.82K  --.-KB/s    in 0s

2019-04-16 22:51:59 (106 MB/s) - ‘kubecluster.sh’ saved [8005/8005]

madhanm@k8smaster1:~$ sudo bash kubecluster.sh --init --clustercidr 10.244.0.0/16 --servicecidr 10.96.0.0/12 --cni flannel --networkplugin vxlan --destination $HOME/kubeadm
++++++++++++++++++++++++++++++++++++++++++++++++++
User Input:
++++++++++++++++++++++++++++++++++++++++++++++++++
Destination      /home/madhanm/kubeadm
Release          1.14.0
ClusterCidr      10.244.0.0/16
ServiceCidr      10.96.0.0/12
CNI              flannel
CRI              dockerd
NetworkPlugin    vxlan
++++++++++++++++++++++++++++++++++++++++++++++++++
Reading package lists... Done
Building dependency tree
Reading state information... Done
Suggested packages:
  ifupdown
The following NEW packages will be installed:
  bridge-utils
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 30.1 kB of archives.
After this operation, 102 kB of additional disk space will be used.
Get:1 http://azure.archive.ubuntu.com/ubuntu bionic/main amd64 bridge-utils amd64 1.5-15ubuntu1 [30.1 kB]
Fetched 30.1 kB in 0s (166 kB/s)
Selecting previously unselected package bridge-utils.
(Reading database ... 55611 files and directories currently installed.)
Preparing to unpack .../bridge-utils_1.5-15ubuntu1_amd64.deb ...
Unpacking bridge-utils (1.5-15ubuntu1) ...
Setting up bridge-utils (1.5-15ubuntu1) ...
Processing triggers for man-db (2.8.3-2ubuntu0.1) ...
Checking Kubernetes binaries
OK
Hit:1 http://azure.archive.ubuntu.com/ubuntu bionic InRelease
Get:2 http://azure.archive.ubuntu.com/ubuntu bionic-updates InRelease [88.7 kB]
Get:3 http://azure.archive.ubuntu.com/ubuntu bionic-backports InRelease [74.6 kB]
Get:4 http://security.ubuntu.com/ubuntu bionic-security InRelease [88.7 kB]
Get:6 http://azure.archive.ubuntu.com/ubuntu bionic-updates/main amd64 Packages [579 kB]
Get:7 http://azure.archive.ubuntu.com/ubuntu bionic-updates/main Translation-en [214 kB]
Get:8 http://azure.archive.ubuntu.com/ubuntu bionic-updates/universe amd64 Packages [861 kB]
Get:9 http://azure.archive.ubuntu.com/ubuntu bionic-updates/universe Translation-en [261 kB]
Get:10 http://azure.archive.ubuntu.com/ubuntu bionic-updates/multiverse amd64 Packages [6636 B]
Get:11 http://azure.archive.ubuntu.com/ubuntu bionic-updates/multiverse Translation-en [3556 B]
Get:5 https://packages.cloud.google.com/apt kubernetes-xenial InRelease [8993 B]
Get:12 http://security.ubuntu.com/ubuntu bionic-security/main amd64 Packages [320 kB]
Get:13 http://security.ubuntu.com/ubuntu bionic-security/main Translation-en [115 kB]
Get:14 http://security.ubuntu.com/ubuntu bionic-security/universe amd64 Packages [240 kB]
Get:15 http://security.ubuntu.com/ubuntu bionic-security/universe Translation-en [137 kB]
Get:16 http://security.ubuntu.com/ubuntu bionic-security/multiverse amd64 Packages [4008 B]
Get:17 http://security.ubuntu.com/ubuntu bionic-security/multiverse Translation-en [2060 B]
Get:18 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 Packages [25.2 kB]
Fetched 3029 kB in 1s (3612 kB/s)
Reading package lists... Done
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following additional packages will be installed:
  conntrack cri-tools kubernetes-cni socat
The following NEW packages will be installed:
  conntrack cri-tools kubeadm kubectl kubelet kubernetes-cni socat
0 upgraded, 7 newly installed, 0 to remove and 43 not upgraded.
Need to get 50.6 MB of archives.
After this operation, 290 MB of additional disk space will be used.
Get:1 http://azure.archive.ubuntu.com/ubuntu bionic/main amd64 conntrack amd64 1:1.4.4+snapshot20161117-6ubuntu2 [30.6 kB]
Get:2 http://azure.archive.ubuntu.com/ubuntu bionic/main amd64 socat amd64 1.7.3.2-2ubuntu2 [342 kB]
Get:3 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 cri-tools amd64 1.12.0-00 [5343 kB]
Get:4 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 kubernetes-cni amd64 0.7.5-00 [6473 kB]
Get:5 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 kubelet amd64 1.14.1-00 [21.5 MB]
Get:6 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 kubectl amd64 1.14.1-00 [8806 kB]
Get:7 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 kubeadm amd64 1.14.1-00 [8150 kB]
Fetched 50.6 MB in 2s (26.8 MB/s)
Selecting previously unselected package conntrack.
(Reading database ... 55639 files and directories currently installed.)
Preparing to unpack .../0-conntrack_1%3a1.4.4+snapshot20161117-6ubuntu2_amd64.deb ...
Unpacking conntrack (1:1.4.4+snapshot20161117-6ubuntu2) ...
Selecting previously unselected package cri-tools.
Preparing to unpack .../1-cri-tools_1.12.0-00_amd64.deb ...
Unpacking cri-tools (1.12.0-00) ...
Selecting previously unselected package kubernetes-cni.
Preparing to unpack .../2-kubernetes-cni_0.7.5-00_amd64.deb ...
Unpacking kubernetes-cni (0.7.5-00) ...
Selecting previously unselected package socat.
Preparing to unpack .../3-socat_1.7.3.2-2ubuntu2_amd64.deb ...
Unpacking socat (1.7.3.2-2ubuntu2) ...
Selecting previously unselected package kubelet.
Preparing to unpack .../4-kubelet_1.14.1-00_amd64.deb ...
Unpacking kubelet (1.14.1-00) ...
Selecting previously unselected package kubectl.
Preparing to unpack .../5-kubectl_1.14.1-00_amd64.deb ...
Unpacking kubectl (1.14.1-00) ...
Selecting previously unselected package kubeadm.
Preparing to unpack .../6-kubeadm_1.14.1-00_amd64.deb ...
Unpacking kubeadm (1.14.1-00) ...
Setting up conntrack (1:1.4.4+snapshot20161117-6ubuntu2) ...
Setting up kubernetes-cni (0.7.5-00) ...
Setting up cri-tools (1.12.0-00) ...
Setting up socat (1.7.3.2-2ubuntu2) ...
Setting up kubelet (1.14.1-00) ...
Created symlink /etc/systemd/system/multi-user.target.wants/kubelet.service → /lib/systemd/system/kubelet.service.
Setting up kubectl (1.14.1-00) ...
Processing triggers for man-db (2.8.3-2ubuntu0.1) ...
Setting up kubeadm (1.14.1-00) ...
net.ipv4.ip_forward = 1
Hit:1 http://security.ubuntu.com/ubuntu bionic-security InRelease
Hit:3 http://azure.archive.ubuntu.com/ubuntu bionic InRelease
Hit:4 http://azure.archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:5 http://azure.archive.ubuntu.com/ubuntu bionic-backports InRelease
Hit:2 https://packages.cloud.google.com/apt kubernetes-xenial InRelease
Reading package lists... Done
Reading package lists... Done
Building dependency tree
Reading state information... Done
ca-certificates is already the newest version (20180409).
curl is already the newest version (7.58.0-2ubuntu3.6).
software-properties-common is already the newest version (0.96.24.32.7).
The following NEW packages will be installed:
  apt-transport-https
0 upgraded, 1 newly installed, 0 to remove and 43 not upgraded.
Need to get 1692 B of archives.
After this operation, 153 kB of additional disk space will be used.
Do you want to continue? [Y/n] Y
Get:1 http://azure.archive.ubuntu.com/ubuntu bionic-updates/universe amd64 apt-transport-https all 1.6.10 [1692 B]
Fetched 1692 B in 0s (16.7 kB/s)
Selecting previously unselected package apt-transport-https.
(Reading database ... 55710 files and directories currently installed.)
Preparing to unpack .../apt-transport-https_1.6.10_all.deb ...
Unpacking apt-transport-https (1.6.10) ...
Setting up apt-transport-https (1.6.10) ...
OK
Hit:1 http://azure.archive.ubuntu.com/ubuntu bionic InRelease
Hit:2 http://azure.archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:3 http://azure.archive.ubuntu.com/ubuntu bionic-backports InRelease
Hit:4 http://security.ubuntu.com/ubuntu bionic-security InRelease
Hit:5 https://packages.cloud.google.com/apt kubernetes-xenial InRelease
Get:6 https://download.docker.com/linux/ubuntu bionic InRelease [64.4 kB]
Get:7 https://download.docker.com/linux/ubuntu bionic/stable amd64 Packages [6046 B]
Fetched 70.5 kB in 1s (78.7 kB/s)
Reading package lists... Done
Hit:1 http://azure.archive.ubuntu.com/ubuntu bionic InRelease
Hit:2 http://azure.archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:3 http://azure.archive.ubuntu.com/ubuntu bionic-backports InRelease
Hit:4 http://security.ubuntu.com/ubuntu bionic-security InRelease
Hit:5 https://packages.cloud.google.com/apt kubernetes-xenial InRelease
Hit:6 https://download.docker.com/linux/ubuntu bionic InRelease
Reading package lists... Done
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following additional packages will be installed:
  aufs-tools cgroupfs-mount containerd.io docker-ce-cli libltdl7 pigz
The following NEW packages will be installed:
  aufs-tools cgroupfs-mount containerd.io docker-ce docker-ce-cli libltdl7 pigz
0 upgraded, 7 newly installed, 0 to remove and 43 not upgraded.
Need to get 50.7 MB of archives.
After this operation, 243 MB of additional disk space will be used.
Do you want to continue? [Y/n] Y
Get:1 http://azure.archive.ubuntu.com/ubuntu bionic/universe amd64 pigz amd64 2.4-1 [57.4 kB]
Get:2 http://azure.archive.ubuntu.com/ubuntu bionic/universe amd64 aufs-tools amd64 1:4.9+20170918-1ubuntu1 [104 kB]
Get:3 http://azure.archive.ubuntu.com/ubuntu bionic/universe amd64 cgroupfs-mount all 1.4 [6320 B]
Get:4 http://azure.archive.ubuntu.com/ubuntu bionic/main amd64 libltdl7 amd64 2.4.6-2 [38.8 kB]
Get:5 https://download.docker.com/linux/ubuntu bionic/stable amd64 containerd.io amd64 1.2.5-1 [19.9 MB]
Get:6 https://download.docker.com/linux/ubuntu bionic/stable amd64 docker-ce-cli amd64 5:18.09.5~3-0~ubuntu-bionic [13.2 MB]
Get:7 https://download.docker.com/linux/ubuntu bionic/stable amd64 docker-ce amd64 5:18.09.5~3-0~ubuntu-bionic [17.4 MB]Fetched 50.7 MB in 3s (14.5 MB/s)
Selecting previously unselected package pigz.
(Reading database ... 55714 files and directories currently installed.)
Preparing to unpack .../0-pigz_2.4-1_amd64.deb ...
Unpacking pigz (2.4-1) ...
Selecting previously unselected package aufs-tools.
Preparing to unpack .../1-aufs-tools_1%3a4.9+20170918-1ubuntu1_amd64.deb ...
Unpacking aufs-tools (1:4.9+20170918-1ubuntu1) ...
Selecting previously unselected package cgroupfs-mount.
Preparing to unpack .../2-cgroupfs-mount_1.4_all.deb ...
Unpacking cgroupfs-mount (1.4) ...
Selecting previously unselected package containerd.io.
Preparing to unpack .../3-containerd.io_1.2.5-1_amd64.deb ...
Unpacking containerd.io (1.2.5-1) ...
Selecting previously unselected package docker-ce-cli.
Preparing to unpack .../4-docker-ce-cli_5%3a18.09.5~3-0~ubuntu-bionic_amd64.deb ...
Unpacking docker-ce-cli (5:18.09.5~3-0~ubuntu-bionic) ...
Selecting previously unselected package docker-ce.
Preparing to unpack .../5-docker-ce_5%3a18.09.5~3-0~ubuntu-bionic_amd64.deb ...
Unpacking docker-ce (5:18.09.5~3-0~ubuntu-bionic) ...
Selecting previously unselected package libltdl7:amd64.
Preparing to unpack .../6-libltdl7_2.4.6-2_amd64.deb ...
Unpacking libltdl7:amd64 (2.4.6-2) ...
Setting up aufs-tools (1:4.9+20170918-1ubuntu1) ...
Setting up containerd.io (1.2.5-1) ...
Created symlink /etc/systemd/system/multi-user.target.wants/containerd.service → /lib/systemd/system/containerd.service.Processing triggers for ureadahead (0.100.0-20) ...
Setting up cgroupfs-mount (1.4) ...
Processing triggers for libc-bin (2.27-3ubuntu1) ...
Processing triggers for systemd (237-3ubuntu10.15) ...
Setting up libltdl7:amd64 (2.4.6-2) ...
Processing triggers for man-db (2.8.3-2ubuntu0.1) ...
Setting up docker-ce-cli (5:18.09.5~3-0~ubuntu-bionic) ...
Setting up pigz (2.4-1) ...
Setting up docker-ce (5:18.09.5~3-0~ubuntu-bionic) ...
update-alternatives: using /usr/bin/dockerd-ce to provide /usr/bin/dockerd (dockerd) in auto mode
Created symlink /etc/systemd/system/multi-user.target.wants/docker.service → /lib/systemd/system/docker.service.
Created symlink /etc/systemd/system/sockets.target.wants/docker.socket → /lib/systemd/system/docker.socket.
Processing triggers for ureadahead (0.100.0-20) ...
Processing triggers for libc-bin (2.27-3ubuntu1) ...
Processing triggers for systemd (237-3ubuntu10.15) ...
[init] Using Kubernetes version: v1.14.1
[preflight] Running pre-flight checks
[preflight] Pulling images required for setting up a Kubernetes cluster
[preflight] This might take a minute or two, depending on the speed of your internet connection
[preflight] You can also perform this action in beforehand using 'kubeadm config images pull'
[kubelet-start] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[kubelet-start] Activating the kubelet service
[certs] Using certificateDir folder "/etc/kubernetes/pki"
[certs] Generating "etcd/ca" certificate and key
[certs] Generating "etcd/healthcheck-client" certificate and key
[certs] Generating "etcd/server" certificate and key
[certs] etcd/server serving cert is signed for DNS names [k8smaster1 localhost] and IPs [10.0.0.4 127.0.0.1 ::1]
[certs] Generating "etcd/peer" certificate and key
[certs] etcd/peer serving cert is signed for DNS names [k8smaster1 localhost] and IPs [10.0.0.4 127.0.0.1 ::1]
[certs] Generating "apiserver-etcd-client" certificate and key
[certs] Generating "ca" certificate and key
[certs] Generating "apiserver" certificate and key
[certs] apiserver serving cert is signed for DNS names [k8smaster1 kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.cluster.local] and IPs [10.96.0.1 10.0.0.4]
[certs] Generating "apiserver-kubelet-client" certificate and key
[certs] Generating "front-proxy-ca" certificate and key
[certs] Generating "front-proxy-client" certificate and key
[certs] Generating "sa" key and public key
[kubeconfig] Using kubeconfig folder "/etc/kubernetes"
[kubeconfig] Writing "admin.conf" kubeconfig file
[kubeconfig] Writing "kubelet.conf" kubeconfig file
[kubeconfig] Writing "controller-manager.conf" kubeconfig file
[kubeconfig] Writing "scheduler.conf" kubeconfig file
[control-plane] Using manifest folder "/etc/kubernetes/manifests"
[control-plane] Creating static Pod manifest for "kube-apiserver"
[control-plane] Creating static Pod manifest for "kube-controller-manager"
[control-plane] Creating static Pod manifest for "kube-scheduler"
[etcd] Creating static Pod manifest for local etcd in "/etc/kubernetes/manifests"
[wait-control-plane] Waiting for the kubelet to boot up the control plane as static Pods from directory "/etc/kubernetes/manifests". This can take up to 4m0s
[kubelet-check] Initial timeout of 40s passed.
[apiclient] All control plane components are healthy after 60.011055 seconds
[upload-config] storing the configuration used in ConfigMap "kubeadm-config" in the "kube-system" Namespace
[kubelet] Creating a ConfigMap "kubelet-config-1.14" in namespace kube-system with the configuration for the kubelets in the cluster
[upload-certs] Skipping phase. Please see --experimental-upload-certs
[mark-control-plane] Marking the node k8smaster1 as control-plane by adding the label "node-role.kubernetes.io/master=''"
[mark-control-plane] Marking the node k8smaster1 as control-plane by adding the taints [node-role.kubernetes.io/master:NoSchedule]
[bootstrap-token] Using token: ov8v69.fwbonc4wxfzp7e2x
[bootstrap-token] Configuring bootstrap tokens, cluster-info ConfigMap, RBAC Roles
[bootstrap-token] configured RBAC rules to allow Node Bootstrap tokens to post CSRs in order for nodes to get long term certificate credentials
[bootstrap-token] configured RBAC rules to allow the csrapprover controller automatically approve CSRs from a Node Bootstrap Token
[bootstrap-token] configured RBAC rules to allow certificate rotation for all node client certificates in the cluster
[bootstrap-token] creating the "cluster-info" ConfigMap in the "kube-public" namespace
[addons] Applied essential addon: CoreDNS
[addons] Applied essential addon: kube-proxy

Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join 10.0.0.4:6443 --token ov8v69.fwbonc4wxfzp7e2x \
    --discovery-token-ca-cert-hash sha256:dc8199e73794a4873d5b4be57f0df637572aad071ce939dc17520365eb344d92
Successfully deployed the cluster
Deploying Networking Plugins
--2019-04-16 22:58:03--  https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 151.101.248.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|151.101.248.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12306 (12K) [text/plain]
Saving to: ‘/home/madhanm/kubeadm/kube-flannel.yml’

kube-flannel.yml              100%[=================================================>]  12.02K  --.-KB/s    in 0s

2019-04-16 22:58:03 (119 MB/s) - ‘/home/madhanm/kubeadm/kube-flannel.yml’ saved [12306/12306]

net.bridge.bridge-nf-call-iptables = 1
podsecuritypolicy.extensions/psp.flannel.unprivileged created
clusterrole.rbac.authorization.k8s.io/flannel created
clusterrolebinding.rbac.authorization.k8s.io/flannel created
serviceaccount/flannel created
configmap/kube-flannel-cfg created
daemonset.extensions/kube-flannel-ds-amd64 created
daemonset.extensions/kube-flannel-ds-arm64 created
daemonset.extensions/kube-flannel-ds-arm created
daemonset.extensions/kube-flannel-ds-ppc64le created
daemonset.extensions/kube-flannel-ds-s390x created
NAME                      DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR                     AGE
kube-flannel-ds-amd64     0         0         0       0            0           beta.kubernetes.io/arch=amd64     0s
kube-flannel-ds-arm       0         0         0       0            0           beta.kubernetes.io/arch=arm       0s
kube-flannel-ds-arm64     0         0         0       0            0           beta.kubernetes.io/arch=arm64     0s
kube-flannel-ds-ppc64le   0         0         0       0            0           beta.kubernetes.io/arch=ppc64le   0s
kube-flannel-ds-s390x     0         0         0       0            0           beta.kubernetes.io/arch=s390x     0s
kube-proxy                0         0         0       0            0           <none>                            3s
--2019-04-16 22:58:06--  https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/flannel/l2bridge/manifests/node-selector-patch.yml
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 151.101.248.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|151.101.248.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 88 [text/plain]
Saving to: ‘/home/madhanm/kubeadm/node-selector-patch.yml’

node-selector-patch.yml       100%[=================================================>]      88  --.-KB/s    in 0s

2019-04-16 22:58:06 (14.2 MB/s) - ‘/home/madhanm/kubeadm/node-selector-patch.yml’ saved [88/88]

daemonset.extensions/kube-flannel-ds-amd64 patched
daemonset.extensions/kube-proxy patched
```