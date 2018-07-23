// Copyright Microsoft Corp.
// All rights reserved.

package common

// Plugin is the parent class that implements behavior common to all plugins.
type Plugin struct {
	Name    string
	Version string
	Options map[string]interface{}
	ErrChan chan error
}

// Plugin base interface.
type PluginApi interface {
	Start(*PluginConfig) error
	Stop()
	GetOption(string) interface{}
	SetOption(string, interface{})
}

// Network internal interface.
type NetAPI interface {
}

// IPAM internal interface.
type IpamApi interface {
}

// Plugin common configuration.
type PluginConfig struct {
	Name    string
	Version string
	NetApi  NetAPI
}

// NewPlugin creates a new Plugin object.
func NewPlugin(name, version string) (*Plugin, error) {
	return &Plugin{
		Name:    name,
		Version: version,
		Options: make(map[string]interface{}),
	}, nil
}

// Initialize initializes the plugin.
func (plugin *Plugin) Initialize(config *PluginConfig) error {
	return nil
}

// Uninitialize cleans up the plugin.
func (plugin *Plugin) Uninitialize() {
}

// GetOption gets the option value for the given key.
func (plugin *Plugin) GetOption(key string) interface{} {
	return plugin.Options[key]
}

// SetOption sets the option value for the given key.
func (plugin *Plugin) SetOption(key string, value interface{}) {
	plugin.Options[key] = value
}
