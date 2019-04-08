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
