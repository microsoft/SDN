// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
)

type CNIPolicyType string

const (
	NetworkPolicy CNIPolicyType = "NetworkPolicy"
	EndpointPolicy CNIPolicyType = "EndpointPolicy"
	OutBoundNatPolicy CNIPolicyType = "OutBoundNatPolicy"
)

type Policy struct {
	Type CNIPolicyType
	Data json.RawMessage
}

