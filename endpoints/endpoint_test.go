// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package endpoints

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewIPEndpoint(t *testing.T) {
	require := require.New(t)

	addr := netip.MustParseAddrPort("192.168.1.1:9651")
	ep := NewIPEndpoint(addr)

	require.Equal(EndpointTypeIP, ep.Type)
	require.Equal(addr, ep.AddrPort)
	require.Equal(uint16(9651), ep.Port)
	require.True(ep.IsIP())
	require.False(ep.IsHostname())
	require.False(ep.IsRNS())
	require.Equal("192.168.1.1:9651", ep.String())
	require.Equal("192.168.1.1", ep.Host())
}

func TestNewHostnameEndpoint(t *testing.T) {
	require := require.New(t)

	ep, err := NewHostnameEndpoint("mynode.example.com", 9651)
	require.NoError(err)

	require.Equal(EndpointTypeHostname, ep.Type)
	require.Equal("mynode.example.com", ep.Hostname)
	require.Equal(uint16(9651), ep.Port)
	require.False(ep.IsIP())
	require.True(ep.IsHostname())
	require.False(ep.IsRNS())
	require.Equal("mynode.example.com:9651", ep.String())
	require.Equal("mynode.example.com", ep.Host())
}

func TestNewHostnameEndpointErrors(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		port     uint16
		wantErr  error
	}{
		{"empty hostname", "", 9651, ErrEmptyHostname},
		{"zero port", "example.com", 0, ErrInvalidPort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewHostnameEndpoint(tt.hostname, tt.port)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestNewRNSEndpoint(t *testing.T) {
	require := require.New(t)

	// 128-bit destination (16 bytes)
	dest := [RNSDestinationLen]byte{
		0xa5, 0xf7, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
		0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
	}

	ep := NewRNSEndpoint(dest)

	require.Equal(EndpointTypeRNS, ep.Type)
	require.Equal(dest, ep.Destination)
	require.Equal(uint16(0), ep.Port) // RNS doesn't use ports
	require.False(ep.IsIP())
	require.False(ep.IsHostname())
	require.True(ep.IsRNS())
	require.Equal("rns://a5f72c3d4e5f60718293a4b5c6d7e8f9", ep.String())
	require.Equal("a5f72c3d4e5f60718293a4b5c6d7e8f9", ep.Host())
}

func TestNewRNSEndpointFromBytes(t *testing.T) {
	require := require.New(t)

	dest := []byte{
		0xa5, 0xf7, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
		0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
	}

	ep, err := NewRNSEndpointFromBytes(dest)
	require.NoError(err)
	require.True(ep.IsRNS())

	// Wrong length should fail
	_, err = NewRNSEndpointFromBytes([]byte{0x01, 0x02})
	require.ErrorIs(err, ErrInvalidDestination)
}

func TestNewRNSEndpointFromHex(t *testing.T) {
	tests := []struct {
		name    string
		hex     string
		wantErr bool
	}{
		{"valid hex", "a5f72c3d4e5f60718293a4b5c6d7e8f9", false},               // 32 chars
		{"valid with prefix", "rns://a5f72c3d4e5f60718293a4b5c6d7e8f9", false}, // 32 chars
		{"uppercase", "A5F72C3D4E5F60718293A4B5C6D7E8F9", false},               // 32 chars
		{"too short", "a5f72c3d", true},
		{"too long", "a5f72c3d4e5f60718293a4b5c6d7e8f9abcd", true},
		{"invalid hex", "zzzz2c3d4e5f60718293a4b5c6d7e8f9", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := NewRNSEndpointFromHex(tt.hex)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.True(t, ep.IsRNS())
			}
		})
	}
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType EndpointType
		wantErr  bool
	}{
		{"IPv4", "192.168.1.1:9651", EndpointTypeIP, false},
		{"IPv6", "[::1]:9651", EndpointTypeIP, false},
		{"hostname", "mynode.example.com:9651", EndpointTypeHostname, false},
		{"RNS with prefix", "rns://a5f72c3d4e5f60718293a4b5c6d7e8f9", EndpointTypeRNS, false}, // 32 chars
		{"RNS bare hex", "a5f72c3d4e5f60718293a4b5c6d7e8f9", EndpointTypeRNS, false},          // 32 chars
		{"invalid", "not-a-valid-endpoint", EndpointTypeHostname, true},                       // no port
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := ParseEndpoint(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantType, ep.Type)
			}
		})
	}
}

func TestEndpointEqual(t *testing.T) {
	require := require.New(t)

	// IP endpoints
	ip1 := NewIPEndpoint(netip.MustParseAddrPort("192.168.1.1:9651"))
	ip2 := NewIPEndpoint(netip.MustParseAddrPort("192.168.1.1:9651"))
	ip3 := NewIPEndpoint(netip.MustParseAddrPort("192.168.1.2:9651"))

	require.True(ip1.Equal(ip2))
	require.False(ip1.Equal(ip3))

	// Hostname endpoints
	host1, _ := NewHostnameEndpoint("example.com", 9651)
	host2, _ := NewHostnameEndpoint("EXAMPLE.COM", 9651) // case insensitive
	host3, _ := NewHostnameEndpoint("other.com", 9651)

	require.True(host1.Equal(host2))
	require.False(host1.Equal(host3))

	// RNS endpoints
	dest1 := [RNSDestinationLen]byte{0xa5, 0xf7, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9}
	dest2 := [RNSDestinationLen]byte{0xa5, 0xf7, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9}
	dest3 := [RNSDestinationLen]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	rns1 := NewRNSEndpoint(dest1)
	rns2 := NewRNSEndpoint(dest2)
	rns3 := NewRNSEndpoint(dest3)

	require.True(rns1.Equal(rns2))
	require.False(rns1.Equal(rns3))

	// Different types are never equal
	require.False(ip1.Equal(host1))
	require.False(ip1.Equal(rns1))
	require.False(host1.Equal(rns1))
}

func TestEndpointBytes(t *testing.T) {
	require := require.New(t)

	// IP endpoint bytes
	ip := NewIPEndpoint(netip.MustParseAddrPort("192.168.1.1:9651"))
	ipBytes := ip.Bytes()
	require.Equal(byte(EndpointTypeIP), ipBytes[0])
	require.Len(ipBytes, 1+16+2) // type + IPv6 + port

	// Hostname endpoint bytes
	host, _ := NewHostnameEndpoint("example.com", 9651)
	hostBytes := host.Bytes()
	require.Equal(byte(EndpointTypeHostname), hostBytes[0])

	// RNS endpoint bytes
	dest := [RNSDestinationLen]byte{0xa5, 0xf7, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9}
	rns := NewRNSEndpoint(dest)
	rnsBytes := rns.Bytes()
	require.Equal(byte(EndpointTypeRNS), rnsBytes[0])
	require.Len(rnsBytes, 1+RNSDestinationLen) // type + destination
	require.Equal(dest[:], rnsBytes[1:])
}

func TestDestinationHex(t *testing.T) {
	require := require.New(t)

	dest := [RNSDestinationLen]byte{
		0xa5, 0xf7, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
		0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
	}

	ep := NewRNSEndpoint(dest)
	hex := ep.DestinationHex()

	require.Len(hex, RNSDestinationLen*2)
	require.Equal("a5f72c3d4e5f60718293a4b5c6d7e8f9", hex) // 32 chars
}

func TestIsHexString(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abcdef0123456789", true},
		{"ABCDEF0123456789", true},
		{"ABCdef123", true},
		{"xyz", false},
		{"12g4", false},
		{"", true}, // empty is valid hex
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			require.Equal(t, tt.want, isHexString(tt.input))
		})
	}
}
