// Copyright Microsoft Corp.
// All rights reserved.

package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"visualstudio.com/containernetworking/cni/cni"
	"visualstudio.com/containernetworking/cni/cni/network"
	"visualstudio.com/containernetworking/cni/common"
)

// Version is populated by make during build.
var version string

// Main is the entry point for CNI network plugin.
func main() {
	var config common.PluginConfig
	config.Version = version

	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
	file, err := os.OpenFile("wincni.log", os.O_CREATE|os.O_WRONLY, os.FileMode(0777))
	if err != nil {
		logrus.SetOutput(file)
	}
	defer file.Close()

	netPlugin, err := network.NewPlugin(&config)
	if err != nil {
		logrus.Errorf("Failed to create network plugin, err:%v", err)
		os.Exit(1)
	}

	err = netPlugin.Start(&config)
	if err != nil {
		logrus.Errorf("Failed to start network plugin, err:%v.\n", err)
		os.Exit(1)
	}

	err = netPlugin.Execute(cni.PluginApi(netPlugin))

	netPlugin.Stop()

	if err != nil {
		logrus.Errorf("Failed to Execute network plugin, err:%v.\n", err)
		os.Exit(1)
	}
}
