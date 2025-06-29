package pp_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/teamgram/teamgram-server/app/interface/gnetway/internal/server/gnet/pp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseV2Header(t *testing.T) {
	tests := []struct {
		name    string
		header  []byte
		src     net.Addr
		dest    net.Addr
		rawTLVs []byte
		isLocal bool
		err     string
	}{
		{
			name: "TCP4 127.0.0.1",
			//                                                                                     VER  IP/TCP LENGTH
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C,
				// IPV4 -------------|  IPV4 ----------------|   SRC PORT   DEST PORT
				0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0xCA, 0x2B, 0x04, 0x01},
			src:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51755},
			dest: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1025},
		},
		{
			name: "UDP4 127.0.0.1",
			//                                                                                          IP/UDP
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x12, 0x00, 0x0C,
				0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0xCA, 0x2B, 0x04, 0x01},
			src:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51755},
			dest: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1025},
		},
		{
			name: "TCP6 Proxy for TCP4 127.0.0.1",
			//                                                                                     VER  IP/TCP   LENGTH
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x00, 0x24,
				// IPV6 -------------------------------------------------------------------------------------|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x01,
				// IPV6 -------------------------------------------------------------------------------------|   SRC PORT   DEST PORT
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x01, 0xCC, 0x4C, 0x04, 0x01},
			src:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 52300},
			dest: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1025},
		},
		{
			name: "TCP6 Maximal",
			//                                                                                     VER  IP/TCP   LENGTH
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x00, 0x24,
				// IPV6 -------------------------------------------------------------------------------------|
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				// IPV6 -------------------------------------------------------------------------------------|   SRC PORT   DEST PORT
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			src:  &net.TCPAddr{IP: net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), Port: 65535},
			dest: &net.TCPAddr{IP: net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), Port: 65535},
		},
		{
			name: "TCP6 Proxy for TCP6 ::1",
			//                                                                                     VER  IP/TCP   LENGTH
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x00, 0x2B,
				// IPV6 -------------------------------------------------------------------------------------|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// IPV6 -------------------------------------------------------------------------------------|   SRC PORT   DEST PORT
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xCF, 0x8F, 0x04, 0x01,
				//TLVs
				0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60},
			src:     &net.TCPAddr{IP: net.ParseIP("::1"), Port: 53135},
			dest:    &net.TCPAddr{IP: net.ParseIP("::1"), Port: 1025},
			rawTLVs: []byte{0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60},
		},
		{
			name: "UDP6 Proxy for UDP6 ::1",
			//                                                                                     VER  IP/TCP   LENGTH
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x22, 0x00, 0x2B,
				// IPV6 -------------------------------------------------------------------------------------|
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// IPV6 -------------------------------------------------------------------------------------|   SRC PORT   DEST PORT
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xCF, 0x8F, 0x04, 0x01,
				//TLVs
				0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60},
			src:     &net.UDPAddr{IP: net.ParseIP("::1"), Port: 53135},
			dest:    &net.UDPAddr{IP: net.ParseIP("::1"), Port: 1025},
			rawTLVs: []byte{0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60},
		},
		{
			name:   "Missing Proto/Family/Length",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21},
			err:    "while parsing proxy proto v2 header: while reading proto, family and length bytes: EOF",
		},
		{
			name:   "Invalid version",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x01, 0x21, 0x00, 0x2B},
			err:    "while parsing proxy proto v2 header: unexpected version number '0' at pos '13'",
		},
		{
			name:   "Invalid length too long",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x08, 0x01},
			err:    "while parsing proxy proto v2 header: header lengh of '2049' is greater than the allowed 2048 bytes",
		},
		{
			name:   "Not enough bytes",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x08, 0x00},
			err:    "while parsing proxy proto v2 header: while reading proto and length bytes: EOF",
		},
		{
			name:    "Local with no trailing bytes",
			header:  []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x20, 0x00, 0x00, 0x00},
			isLocal: true,
		},
		{
			name: "Local with trailing bytes (TLVs)",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x20, 0xFF, 0x00, 0x07,
				0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60},
			rawTLVs: []byte{0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60},
			isLocal: true,
		},
		{
			name:   "Proxy with zero byte header",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x00, 0x00, 0x00},
			err:    "while parsing proxy proto v2 header: expected address but got zero length header",
		},
		{
			name:   "Invalid length for IPV4",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x01, 0xFF},
			err:    "while parsing proxy proto v2 header: expected 12 bytes for IPV4 address",
		},
		{
			name:   "Invalid length for IPV6",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x00, 0x01, 0xFF},
			err:    "while parsing proxy proto v2 header: expected 36 bytes for IPV6 address",
		},
		{
			name:   "Unix Socket Not Implemented",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x31, 0x00, 0x01, 0xFF},
			err:    "while parsing proxy proto v2 header: Received UNIX socket proxy command, Currently not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.header)
			h, err := pp.ReadHeader(r)
			if err != nil {
				require.Equal(t, err.Error(), tt.err)
				return
			}
			require.NotNil(t, h)
			assert.Equal(t, tt.dest, h.Destination)
			assert.Equal(t, tt.src, h.Source)
			assert.Equal(t, tt.rawTLVs, h.RawTLVs)
			assert.Equal(t, 2, h.Version)
			assert.Equal(t, tt.isLocal, h.IsLocal)
		})
	}
}

func TestReadV2Header(t *testing.T) {
	//                                                                                      VER  IP/TCP LENGTH
	header := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C,
		// IPV4 -------------|  IPV4 ----------------|   SRC PORT   DEST PORT
		0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0xCA, 0x2B, 0x04, 0x01}

	r := bytes.NewReader(header)
	h, err := pp.ReadV2Header(r)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1025}, h.Destination)
	assert.Equal(t, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51755}, h.Source)
	assert.Equal(t, 2, h.Version)
	assert.Equal(t, false, h.IsLocal)

}

func TestHeader_ParseTLVs(t *testing.T) {
	tests := []struct {
		header pp.Header
		m      map[byte][]byte
		name   string
		err    string
	}{
		{
			name:   "CRC",
			header: pp.Header{RawTLVs: []byte{0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60}},
			m: map[byte][]byte{
				0x03: {0xFD, 0x16, 0xEE, 0x60},
			},
		},
		{
			name: "CRC and NoOp",
			header: pp.Header{RawTLVs: []byte{
				0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60,
				0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			}},
			m: map[byte][]byte{
				0x03: {0xFD, 0x16, 0xEE, 0x60},
				0x04: {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			},
		},
		{
			name: "Length to long",
			header: pp.Header{RawTLVs: []byte{
				0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
			}},
			err: "TLV '0x4' length '6' is larger than trailing header",
		},
		{
			name: "Zero Length",
			header: pp.Header{RawTLVs: []byte{
				0x04, 0x00, 0x00,
				0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60,
			}},
			m: map[byte][]byte{
				0x03: {0xFD, 0x16, 0xEE, 0x60},
				0x04: {},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := tt.header.ParseTLVs()
			if err != nil {
				require.Equal(t, err.Error(), tt.err)
				return
			}
			assert.Equal(t, tt.m, m)
		})
	}

}

func BenchmarkReadHeaderV2(b *testing.B) {

	tests := []struct {
		name   string
		header []byte
	}{

		{
			name: "TCP6-With-TLVs",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x00, 0x2B,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xCF, 0x8F, 0x04, 0x01,
				0x03, 0x00, 0x04, 0xFD, 0x16, 0xEE, 0x60},
		},
		{
			name: "TCP6-Minimal",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x00, 0x24,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x01, 0xCC, 0x4C, 0x04, 0x01},
		},
		{
			name: "TCP6-Maximal",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x00, 0x24,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name: "TCP4-Minimal",
			header: []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C,
				0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0xCA, 0x2B, 0x04, 0x01},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				r := bytes.NewReader(tt.header)
				_, err := pp.ReadHeader(r)
				if err != nil {
					b.Errorf("ReadHeader err: %s", err)
				}
			}
		})
	}
}
