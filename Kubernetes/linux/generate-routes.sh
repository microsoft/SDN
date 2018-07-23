#!/bin/bash
CLUSTER=$1

sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING ! -d $CLUSTER.0.0/16 \
              -m addrtype ! --dst-type LOCAL -j MASQUERADE
sudo sysctl -w net.ipv4.ip_forward=1

sudo route add -net $CLUSTER.0.0 netmask 255.255.0.0 dev eth0
sudo route add -net $CLUSTER.1.0 netmask 255.255.255.0 gw $CLUSTER.1.2 dev eth0
