// Copyright Microsoft Corp.
// All rights reserved.

package cni

import (
	"visualstudio.com/containernetworking/cni/common"

	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniVers "github.com/containernetworking/cni/pkg/version"
)

// Plugin is the parent class for CNI plugins.
type Plugin struct {
	*common.Plugin
}

// NewPlugin creates a new CNI plugin.
func NewPlugin(name, version string) (*Plugin, error) {
	// Setup base plugin.
	plugin, err := common.NewPlugin(name, version)
	if err != nil {
		return nil, err
	}

	return &Plugin{
		Plugin: plugin,
	}, nil
}

// Initialize initializes the plugin.
func (plugin *Plugin) Initialize(config *common.PluginConfig) error {
	// Initialize the base plugin.
	plugin.Plugin.Initialize(config)
	return nil
}

// Uninitialize uninitializes the plugin.
func (plugin *Plugin) Uninitialize() {
	plugin.Plugin.Uninitialize()
}

// Execute executes the CNI command.
func (plugin *Plugin) Execute(api PluginApi) error {
	// Set supported CNI versions.
	pluginInfo := cniVers.PluginSupports(Version)

	// Parse args and call the appropriate cmd handler.
	cniErr := cniSkel.PluginMainWithError(api.Add, api.Delete, pluginInfo)
	if cniErr != nil {
		cniErr.Print()
		return cniErr
	}

	return nil
}
