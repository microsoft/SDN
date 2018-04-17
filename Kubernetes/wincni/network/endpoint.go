// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"net"
	"strings"
	"encoding/json"

	"github.com/Microsoft/hcsshim"
)

// EndpointInfo contains read-only information about an endpoint.
// Datastore for NetworkInfo. Store this if required
type EndpointInfo struct {
	ID          string
	Name        string
	NetworkID   string
	IPAddress   net.IP
	MacAddress  net.HardwareAddr
	Gateway     net.IP
	Routes      []RouteInfo
	Policies    []Policy
	Subnet      net.IPNet
	DNS         DNSInfo
	ContainerID string
}

// RouteInfo contains information about an IP route.
type RouteInfo struct {
	Destination net.IPNet
	Gateway     net.IP
}

// Get HNSEndpoint from EndpointInfo
func (endpoint *EndpointInfo) GetHNSEndpointConfig() *hcsshim.HNSEndpoint {
	hnsep := &hcsshim.HNSEndpoint{
		Name:           endpoint.Name,
		Id:             endpoint.ID,
		VirtualNetwork: endpoint.NetworkID,
		DNSServerList:  strings.Join(endpoint.DNS.Servers, ","),
		DNSSuffix:      endpoint.DNS.Suffix,
		MacAddress:     endpoint.MacAddress.String(),
		GatewayAddress: endpoint.Gateway.String(),
		IPAddress:      endpoint.IPAddress,
		Policies:       GetHNSEndpointPolicies(endpoint.Policies),
	}

	return hnsep;
}

// Get EndpointInfo from HNSEndpoint
func GetEndpointInfo(hnsEndpoint *hcsshim.HNSEndpoint) *EndpointInfo {
	macAddress, _ := net.ParseMAC(hnsEndpoint.MacAddress)
	return &EndpointInfo{
		Name:       hnsEndpoint.Name,
		ID:         hnsEndpoint.Id,
		NetworkID:  hnsEndpoint.VirtualNetwork,
		MacAddress: macAddress,
		Gateway:    net.ParseIP(hnsEndpoint.GatewayAddress),
		IPAddress:  hnsEndpoint.IPAddress,
		Policies:   GetEndpointPolicies(hnsEndpoint.Policies),
	}
}
func (endpoint *EndpointInfo) HotAttachEndpoint(containerID string) error {
	return hcsshim.HotAttachEndpoint(containerID, endpoint.ID)
}

func (endpoint *EndpointInfo) DetachEndpoint() error {
	// Detach is not exposed via hcsshim

	return nil
}

func (endpoint *EndpointInfo) HotDetachEndpoint(containerID string) error {
	return hcsshim.HotDetachEndpoint(containerID, endpoint.ID)
}


// GetPolicies
func GetEndpointPolicies(jsonPolicies []json.RawMessage) []Policy {
	var policies []Policy
	for _, jsonPolicy := range jsonPolicies {
		policies = append(policies,  Policy{Type:EndpointPolicy, Data:jsonPolicy})
	}

	return policies
}

// GetHNSPolicies
func GetHNSEndpointPolicies(policies []Policy) []json.RawMessage {
	var jsonPolicies []json.RawMessage
	for _, policy := range policies {
		if policy.Type == EndpointPolicy {
			jsonPolicies = append(jsonPolicies, policy.Data)
		}
	}

	return jsonPolicies
}

func GetHNSNatPolicy(externalPort int, internalPort int, protocol string) Policy {
	rawPolicy, _ := json.Marshal(&hcsshim.NatPolicy{
		Type:         "NAT",
		ExternalPort: uint16(externalPort),
		InternalPort: uint16(internalPort),
		Protocol:     protocol,
	})

	return Policy{
		Type: EndpointPolicy,
		Data: rawPolicy,
	}
}