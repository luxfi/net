// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ips

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/luxfi/codec/wrappers"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/ids"
	"github.com/luxfi/staking"
)

var (
	ErrInvalidEndpoint = errors.New("invalid endpoint")
	ErrEmptyHostname   = errors.New("empty hostname")
	ErrInvalidPort     = errors.New("invalid port")
)

// EndpointType indicates whether an endpoint is IP-based or hostname-based.
type EndpointType uint8

const (
	EndpointTypeIP       EndpointType = 0
	EndpointTypeHostname EndpointType = 1

	// Maximum hostname length per RFC 1035
	MaxHostnameLen = 253
)

// Endpoint represents a network endpoint that can be either:
// - An IP address and port (traditional, for datacenter validators)
// - A hostname and port (for nodes behind proxies/tunnels)
//
// This supports the "laptop validator" use case where a node advertises
// a hostname (e.g., mynode.example.com:9651) instead of an IP.
type Endpoint struct {
	// Type indicates whether this is an IP or hostname endpoint
	Type EndpointType

	// AddrPort is set when Type == EndpointTypeIP
	AddrPort netip.AddrPort

	// Hostname is set when Type == EndpointTypeHostname
	Hostname string

	// Port is always set
	Port uint16
}

// NewIPEndpoint creates an endpoint from an IP address and port.
func NewIPEndpoint(addr netip.AddrPort) Endpoint {
	return Endpoint{
		Type:     EndpointTypeIP,
		AddrPort: addr,
		Port:     addr.Port(),
	}
}

// NewHostnameEndpoint creates an endpoint from a hostname and port.
func NewHostnameEndpoint(hostname string, port uint16) (Endpoint, error) {
	if hostname == "" {
		return Endpoint{}, ErrEmptyHostname
	}
	if len(hostname) > MaxHostnameLen {
		return Endpoint{}, fmt.Errorf("%w: hostname too long (%d > %d)", ErrInvalidEndpoint, len(hostname), MaxHostnameLen)
	}
	if port == 0 {
		return Endpoint{}, ErrInvalidPort
	}
	return Endpoint{
		Type:     EndpointTypeHostname,
		Hostname: hostname,
		Port:     port,
	}, nil
}

// ParseEndpoint parses a string like "1.2.3.4:9651" or "mynode.example.com:9651".
func ParseEndpoint(s string) (Endpoint, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: %v", ErrInvalidEndpoint, err)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: invalid port: %v", ErrInvalidPort, err)
	}
	if port == 0 {
		return Endpoint{}, ErrInvalidPort
	}

	// Try to parse as IP first
	if ip, err := netip.ParseAddr(host); err == nil {
		return Endpoint{
			Type:     EndpointTypeIP,
			AddrPort: netip.AddrPortFrom(ip, uint16(port)),
			Port:     uint16(port),
		}, nil
	}

	// Treat as hostname
	return NewHostnameEndpoint(host, uint16(port))
}

// IsIP returns true if this is an IP-based endpoint.
func (e Endpoint) IsIP() bool {
	return e.Type == EndpointTypeIP
}

// IsHostname returns true if this is a hostname-based endpoint.
func (e Endpoint) IsHostname() bool {
	return e.Type == EndpointTypeHostname
}

// String returns the endpoint as a dial-able string.
func (e Endpoint) String() string {
	if e.Type == EndpointTypeIP {
		return e.AddrPort.String()
	}
	return net.JoinHostPort(e.Hostname, strconv.Itoa(int(e.Port)))
}

// Host returns the host part (IP or hostname).
func (e Endpoint) Host() string {
	if e.Type == EndpointTypeIP {
		return e.AddrPort.Addr().String()
	}
	return e.Hostname
}

// Equal compares two endpoints.
func (e Endpoint) Equal(other Endpoint) bool {
	if e.Type != other.Type {
		return false
	}
	if e.Type == EndpointTypeIP {
		return e.AddrPort == other.AddrPort
	}
	return strings.EqualFold(e.Hostname, other.Hostname) && e.Port == other.Port
}

// Bytes returns the canonical byte representation for signing.
// Format:
//   - Type (1 byte)
//   - If IP: IPv6 addr (16 bytes) + port (2 bytes)
//   - If Hostname: hostname length (2 bytes) + hostname + port (2 bytes)
func (e Endpoint) Bytes() []byte {
	if e.Type == EndpointTypeIP {
		p := wrappers.Packer{
			Bytes: make([]byte, 1+net.IPv6len+wrappers.ShortLen),
		}
		p.PackByte(byte(EndpointTypeIP))
		addrBytes := e.AddrPort.Addr().As16()
		p.PackFixedBytes(addrBytes[:])
		p.PackShort(e.Port)
		return p.Bytes
	}

	// Hostname endpoint
	hostBytes := []byte(e.Hostname)
	p := wrappers.Packer{
		Bytes: make([]byte, 1+wrappers.ShortLen+len(hostBytes)+wrappers.ShortLen),
	}
	p.PackByte(byte(EndpointTypeHostname))
	p.PackShort(uint16(len(hostBytes)))
	p.PackFixedBytes(hostBytes)
	p.PackShort(e.Port)
	return p.Bytes
}

// ClaimedEndpoint is a self-contained proof that a peer is claiming ownership
// of an endpoint at a given time. Extends ClaimedIPPort to support hostnames.
type ClaimedEndpoint struct {
	// The peer's certificate.
	Cert *staking.Certificate
	// The claimed endpoint (IP or hostname).
	Endpoint Endpoint
	// The time the peer claimed to own this endpoint.
	Timestamp uint64
	// [Cert]'s signature over the endpoint and timestamp.
	Signature []byte
	// NodeID derived from the peer certificate.
	NodeID ids.NodeID
	// GossipID derived from the nodeID and timestamp.
	GossipID ids.ID

	// Legacy: For backward compatibility, if this is an IP endpoint,
	// we also store it in the legacy format.
	LegacyIP *ClaimedIPPort
}

// NewClaimedEndpoint creates a new claimed endpoint.
func NewClaimedEndpoint(
	cert *staking.Certificate,
	endpoint Endpoint,
	timestamp uint64,
	signature []byte,
) *ClaimedEndpoint {
	ce := &ClaimedEndpoint{
		Cert:      cert,
		Endpoint:  endpoint,
		Timestamp: timestamp,
		Signature: signature,
		NodeID:    ids.NodeIDFromCert(cert),
	}

	// Compute GossipID from nodeID + timestamp
	packer := wrappers.Packer{
		Bytes: make([]byte, preimageLen),
	}
	packer.PackFixedBytes(ce.NodeID[:])
	packer.PackLong(timestamp)
	ce.GossipID = hash.ComputeHash256Array(packer.Bytes)

	// For backward compatibility with IP endpoints
	if endpoint.IsIP() {
		ce.LegacyIP = NewClaimedIPPort(cert, endpoint.AddrPort, timestamp, signature)
	}

	return ce
}

// ToClaimedIPPort converts to legacy format if this is an IP endpoint.
// Returns nil if this is a hostname endpoint.
func (ce *ClaimedEndpoint) ToClaimedIPPort() *ClaimedIPPort {
	if ce.LegacyIP != nil {
		return ce.LegacyIP
	}
	if !ce.Endpoint.IsIP() {
		return nil
	}
	return NewClaimedIPPort(ce.Cert, ce.Endpoint.AddrPort, ce.Timestamp, ce.Signature)
}

// FromClaimedIPPort creates a ClaimedEndpoint from a legacy ClaimedIPPort.
func FromClaimedIPPort(ip *ClaimedIPPort) *ClaimedEndpoint {
	return &ClaimedEndpoint{
		Cert:      ip.Cert,
		Endpoint:  NewIPEndpoint(ip.AddrPort),
		Timestamp: ip.Timestamp,
		Signature: ip.Signature,
		NodeID:    ip.NodeID,
		GossipID:  ip.GossipID,
		LegacyIP:  ip,
	}
}

// Size returns the approximate size of the binary representation.
func (ce *ClaimedEndpoint) Size() int {
	endpointSize := 1 // type byte
	if ce.Endpoint.IsIP() {
		endpointSize += net.IPv6len + 2
	} else {
		endpointSize += 2 + len(ce.Endpoint.Hostname) + 2
	}
	return endpointSize + 8 + len(ce.Cert.Raw) + len(ce.Signature)
}
