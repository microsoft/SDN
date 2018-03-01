KUBEPATH="$HOME/kube"

sudo pkill hyperkube
docker ps -a  |  awk '{print $1}' | xargs --no-run-if-empty docker rm -f

sudo rm -rf $KUBEPATH/etcd/datakube
sudo rm -rf $KUBEPATH/log/*
sudo rm -rf ~/.kube

