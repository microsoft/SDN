KUBEPATH="$HOME/kube"

OLDIP="10.124.25.151"
NEWIP=`ifconfig eth0 | awk '/inet addr/{print substr($2,6)}'`

sudo sed -i "s/${OLDIP}/${NEWIP}/g" /etc/hosts
sudo sed -i "s/nameserver/#nameserver/g" /etc/resolv.conf
sed -i "s/${OLDIP}/${NEWIP}/g" $KUBEPATH/kubectlconfig.sh
sed -i "s/${OLDIP}/${NEWIP}/g" $KUBEPATH/certs/openssl.cnf
sed -i "s/${OLDIP}/${NEWIP}/g" $KUBEPATH/manifest/kube-apiserver.yaml
sed -i "s/${OLDIP}/${NEWIP}/g" $KUBEPATH/manifest/kube-etcd.yaml

chmod +x $KUBEPATH/bin/kubectl
chmod +x $KUBEPATH/cnibin/hyperkube
chmod +x $KUBEPATH/proxybin/hyperkube


# Generate Certificates
bash $KUBEPATH/certs/generate_certs.sh
sudo bash $KUBEPATH/createcidr.sh
bash $KUBEPATH/kubectlconfig.sh

sudo bash $KUBEPATH/start-kubelet.sh
sudo bash $KUBEPATH/start-kubeproxy.sh
sudo bash $KUBEPATH/addRoute.sh

