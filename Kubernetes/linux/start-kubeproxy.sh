#/bin/bash
KUBEPATH="$HOME/kube"
KUBECONFIG="$HOME/.kube/config"
KUBEMANIFEST="$KUBEPATH/manifest"
CLUSTER=$1

./bin/hyperkube kube-proxy --kubeconfig=$KUBECONFIG \
    --cluster-cidr=$CLUSTER.0.0/16
