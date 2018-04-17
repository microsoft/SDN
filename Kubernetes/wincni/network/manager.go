// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/sirupsen/logrus"
	"visualstudio.com/containernetworking/cni/common"
)

type HTTPRequest string

const (
	// GET http request
	GET HTTPRequest = "GET"
	// POST
	POST HTTPRequest = "POST"
	// DELETE
	DELETE HTTPRequest = "DELETE"
)

// NetworkManager manages the set of container networking resources.
type networkManager struct {
	Version   string
	TimeStamp time.Time
	sync.Mutex
}

// Manager API.
type Manager interface {
	Initialize(config *common.PluginConfig) error
	Uninitialize()

	CreateNetwork(config *NetworkInfo) (*NetworkInfo, error)
	DeleteNetwork(networkID string) error
	GetNetwork(networkID string) (*NetworkInfo, error)
	GetNetworkByName(networkName string) (*NetworkInfo, error)

	CreateEndpoint(networkID string, epInfo *EndpointInfo) (*EndpointInfo, error)
	DeleteEndpoint(endpointID string) error
	GetEndpoint(endpointID string) (*EndpointInfo, error)
	GetEndpointByName(endpointName string) (*EndpointInfo, error)
	AttachEndpointToContainer(endpointName string, containerID string) error
	DetachEndpointFromContainer(endpointName string, containerID string) error
}

// Creates a NewManager ....
func NewManager() (Manager, error) {
	nm := &networkManager{}

	return nm, nil
}

// Initialize configures network manager.
func (nm *networkManager) Initialize(config *common.PluginConfig) error {
	nm.Version = config.Version
	return nil
}

// Uninitialize cleans up network manager.
func (nm *networkManager) Uninitialize() {
}

//
// NetworkManager API
//
//

// CreateNetwork creates a new container network.
func (nm *networkManager) CreateNetwork(config *NetworkInfo) (*NetworkInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	hnsNetworkConfig := config.GetHNSNetworkConfig()

	jsonString, err := json.Marshal(hnsNetworkConfig)
	if err != nil {
		return nil, err
	}

	configuration := string(jsonString)
	hnsnetwork, err := hcsshim.HNSNetworkRequest(string(POST), "", configuration)
	if err != nil {
		return nil, err
	}

	// Update the ID of the
	return GetNetworkInfo(hnsnetwork), err
}

// DeleteNetwork deletes an existing container network.
func (nm *networkManager) DeleteNetwork(networkID string) error {
	nm.Lock()
	defer nm.Unlock()

	_, err := hcsshim.HNSNetworkRequest(string(DELETE), networkID, "")
	if err != nil {
		return err
	}
	return nil
}

// GetNetworkInfo returns information about the given network.
func (nm *networkManager) GetNetwork(networkID string) (*NetworkInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	hnsresponse, err := hcsshim.HNSNetworkRequest(string(GET), networkID, "")
	if err != nil {
		return nil, err
	}

	jsonResponse, err := json.Marshal(hnsresponse)
	logrus.Debugf("HNSNetwork GET Response=%v", string(jsonResponse))

	return GetNetworkInfo(hnsresponse), nil
}

// GetNetworkInfo returns information about the given network.
func (nm *networkManager) GetNetworkByName(networkName string) (*NetworkInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return nil, err
	}

	return GetNetworkInfo(hnsNetwork), nil
}

// CreateEndpoint creates a new container endpoint & connects it to container
func (nm *networkManager) CreateEndpoint(networkID string, epInfo *EndpointInfo) (*EndpointInfo, error) {
	nm.Lock()
	defer nm.Unlock()
	epInfo.NetworkID = networkID
	hnsEndpointConfig := epInfo.GetHNSEndpointConfig()
	hnsendpoint, err := hnsEndpointConfig.Create()
	if err != nil {
		return nil, err
	}
	return GetEndpointInfo(hnsendpoint), err
}

// DeleteEndpoint deletes an existing container endpoint, after disconnecting from container
func (nm *networkManager) DeleteEndpoint(endpointID string) error {
	nm.Lock()
	defer nm.Unlock()

	_, err := hcsshim.HNSEndpointRequest(string(DELETE), endpointID, "")
	return err
}

// GetEndpointInfo returns information about the given endpoint.
func (nm *networkManager) GetEndpoint(endpointID string) (*EndpointInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	hnsresponse, err := hcsshim.HNSEndpointRequest(string(GET), endpointID, "")
	if err != nil {
		return nil, err
	}

	jsonResponse, err := json.Marshal(hnsresponse)
	logrus.Debugf("HNSEndpoint DELETE Response=%v", string(jsonResponse))

	return GetEndpointInfo(hnsresponse), nil
}

// GetNetworkInfo returns information about the given network.
func (nm *networkManager) GetEndpointByName(endpointName string) (*EndpointInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err != nil {
		return nil, err
	}

	return GetEndpointInfo(hnsEndpoint), nil
}

// GetNetworkInfo returns information about the given network.
func (nm *networkManager) AttachEndpointToContainer(endpointName string, containerID string) error {
	nm.Lock()
	defer nm.Unlock()

	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err != nil {
		return err
	}
	// Compartment is optional
	return hnsEndpoint.ContainerAttach(containerID, 0)
}

// GetNetworkInfo returns information about the given network.
func (nm *networkManager) DetachEndpointFromContainer(endpointName string, containerID string) error {
	nm.Lock()
	defer nm.Unlock()

	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err != nil {
		return err
	}
	// Compartment is optional
	return hnsEndpoint.ContainerDetach(containerID)
}
