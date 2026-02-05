// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package endpoints

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
	ErrInvalidEndpoint    = errors.New("invalid endpoint")
	ErrEmptyHostname      = errors.New("empty hostname")
	ErrInvalidPort        = errors.New("invalid port")
	ErrInvalidDestination = errors.New("invalid RNS destination")
)

// EndpointType indicates whether an endpoint is IP-based or hostname-based.
type EndpointType uint8

const (
	EndpointTypeIP       EndpointType = 0
	EndpointTypeHostname EndpointType = 1
	EndpointTypeRNS      EndpointType = 2 // Reticulum Network Stack destination

	// Maximum hostname length per RFC 1035
	MaxHostnameLen = 253

	// RNS destination is a 128-bit truncated hash
	RNSDestinationLen = 16

	// RNS destination string prefix for parsing
	RNSPrefix = "rns://"
)

// Endpoint represents a network endpoint that can be either:
// - An IP address and port (traditional, for datacenter validators)
// - A hostname and port (for nodes behind proxies/tunnels)
// - An RNS destination (Reticulum Network Stack, for mesh/LoRa/offline-first)
//
// This supports the "laptop validator" use case where a node advertises
// a hostname (e.g., mynode.example.com:9651) instead of an IP, and the
// "mesh validator" use case where a node uses Reticulum's medium-agnostic
// addressing (e.g., rns://a5f72c...).
type Endpoint struct {
	// Type indicates whether this is an IP, hostname, or RNS endpoint
	Type EndpointType

	// AddrPort is set when Type == EndpointTypeIP
	AddrPort netip.AddrPort

	// Hostname is set when Type == EndpointTypeHostname
	Hostname string

	// Destination is set when Type == EndpointTypeRNS
	// This is a 128-bit truncated hash of the Reticulum identity
	Destination [RNSDestinationLen]byte

	// Port is set for IP and Hostname endpoints (0 for RNS)
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

// NewRNSEndpoint creates an endpoint from a Reticulum destination hash.
// The destination is a 128-bit (16-byte) truncated hash of the RNS identity.
func NewRNSEndpoint(destination [RNSDestinationLen]byte) Endpoint {
	return Endpoint{
		Type:        EndpointTypeRNS,
		Destination: destination,
		Port:        0, // RNS doesn't use ports
	}
}

// NewRNSEndpointFromBytes creates an RNS endpoint from a byte slice.
func NewRNSEndpointFromBytes(dest []byte) (Endpoint, error) {
	if len(dest) != RNSDestinationLen {
		return Endpoint{}, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidDestination, RNSDestinationLen, len(dest))
	}
	var destination [RNSDestinationLen]byte
	copy(destination[:], dest)
	return NewRNSEndpoint(destination), nil
}

// NewRNSEndpointFromHex creates an RNS endpoint from a hex string.
func NewRNSEndpointFromHex(hexStr string) (Endpoint, error) {
	// Strip rns:// prefix if present
	hexStr = strings.TrimPrefix(hexStr, RNSPrefix)

	if len(hexStr) != RNSDestinationLen*2 {
		return Endpoint{}, fmt.Errorf("%w: expected %d hex chars, got %d", ErrInvalidDestination, RNSDestinationLen*2, len(hexStr))
	}

	var destination [RNSDestinationLen]byte
	for i := 0; i < RNSDestinationLen; i++ {
		b, err := strconv.ParseUint(hexStr[i*2:i*2+2], 16, 8)
		if err != nil {
			return Endpoint{}, fmt.Errorf("%w: invalid hex at position %d: %v", ErrInvalidDestination, i*2, err)
		}
		destination[i] = byte(b)
	}
	return NewRNSEndpoint(destination), nil
}

// ParseEndpoint parses a string like:
// - "1.2.3.4:9651" (IP endpoint)
// - "mynode.example.com:9651" (hostname endpoint)
// - "rns://a5f72c3d..." (RNS destination, 32 hex chars)
func ParseEndpoint(s string) (Endpoint, error) {
	// Check for RNS destination
	if strings.HasPrefix(s, RNSPrefix) {
		return NewRNSEndpointFromHex(s)
	}

	// Check for bare hex that looks like an RNS destination (32 hex chars)
	if len(s) == RNSDestinationLen*2 && isHexString(s) {
		return NewRNSEndpointFromHex(s)
	}

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

// isHexString returns true if s contains only valid hex characters.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// IsIP returns true if this is an IP-based endpoint.
func (e Endpoint) IsIP() bool {
	return e.Type == EndpointTypeIP
}

// IsHostname returns true if this is a hostname-based endpoint.
func (e Endpoint) IsHostname() bool {
	return e.Type == EndpointTypeHostname
}

// IsRNS returns true if this is an RNS (Reticulum) endpoint.
func (e Endpoint) IsRNS() bool {
	return e.Type == EndpointTypeRNS
}

// String returns the endpoint as a dial-able string.
func (e Endpoint) String() string {
	switch e.Type {
	case EndpointTypeIP:
		return e.AddrPort.String()
	case EndpointTypeRNS:
		return RNSPrefix + e.DestinationHex()
	default: // EndpointTypeHostname
		return net.JoinHostPort(e.Hostname, strconv.Itoa(int(e.Port)))
	}
}

// DestinationHex returns the RNS destination as a lowercase hex string.
func (e Endpoint) DestinationHex() string {
	const hexChars = "0123456789abcdef"
	buf := make([]byte, RNSDestinationLen*2)
	for i, b := range e.Destination {
		buf[i*2] = hexChars[b>>4]
		buf[i*2+1] = hexChars[b&0x0f]
	}
	return string(buf)
}

// Host returns the host part (IP, hostname, or RNS destination).
func (e Endpoint) Host() string {
	switch e.Type {
	case EndpointTypeIP:
		return e.AddrPort.Addr().String()
	case EndpointTypeRNS:
		return e.DestinationHex()
	default: // EndpointTypeHostname
		return e.Hostname
	}
}

// Equal compares two endpoints.
func (e Endpoint) Equal(other Endpoint) bool {
	if e.Type != other.Type {
		return false
	}
	switch e.Type {
	case EndpointTypeIP:
		return e.AddrPort == other.AddrPort
	case EndpointTypeRNS:
		return e.Destination == other.Destination
	default: // EndpointTypeHostname
		return strings.EqualFold(e.Hostname, other.Hostname) && e.Port == other.Port
	}
}

// Bytes returns the canonical byte representation for signing.
// Format:
//   - Type (1 byte)
//   - If IP: IPv6 addr (16 bytes) + port (2 bytes)
//   - If Hostname: hostname length (2 bytes) + hostname + port (2 bytes)
//   - If RNS: destination (16 bytes)
func (e Endpoint) Bytes() []byte {
	switch e.Type {
	case EndpointTypeIP:
		p := wrappers.Packer{
			Bytes: make([]byte, 1+net.IPv6len+wrappers.ShortLen),
		}
		p.PackByte(byte(EndpointTypeIP))
		addrBytes := e.AddrPort.Addr().As16()
		p.PackFixedBytes(addrBytes[:])
		p.PackShort(e.Port)
		return p.Bytes

	case EndpointTypeRNS:
		p := wrappers.Packer{
			Bytes: make([]byte, 1+RNSDestinationLen),
		}
		p.PackByte(byte(EndpointTypeRNS))
		p.PackFixedBytes(e.Destination[:])
		return p.Bytes

	default: // EndpointTypeHostname
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
	switch ce.Endpoint.Type {
	case EndpointTypeIP:
		endpointSize += net.IPv6len + 2
	case EndpointTypeRNS:
		endpointSize += RNSDestinationLen
	default: // EndpointTypeHostname
		endpointSize += 2 + len(ce.Endpoint.Hostname) + 2
	}
	return endpointSize + 8 + len(ce.Cert.Raw) + len(ce.Signature)
}
