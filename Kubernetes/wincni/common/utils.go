// Copyright Microsoft Corp.
// All rights reserved.

package common

import (
	"net"

	"github.com/sirupsen/logrus"
)

// LogNetworkInterfaces logs the host's network interfaces in the default namespace.
func LogNetworkInterfaces() {
	interfaces, err := net.Interfaces()
	if err != nil {
		logrus.Errorf("Failed to query network interfaces, err:%v", err)
		return
	}

	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		logrus.Debugf("[net] Network interface: %+v with IP addresses: %+v", iface, addrs)
	}
}
