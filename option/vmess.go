package option

import "github.com/sagernet/sing/common/json/badoption"

type VMessInboundOptions struct {
	ListenOptions
	Users []VMessUser `json:"users,omitempty"`
	InboundTLSOptionsContainer
	Multiplex *InboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions   `json:"transport,omitempty"`
	// for v2bx: requests that cannot be served are replayed to Fallback;
	// without one they are drained until the handshake deadline.
	Fallback          *ServerOptions               `json:"fallback,omitempty"`
	FallbackForALPN   map[string]*ServerOptions    `json:"fallback_for_alpn,omitempty"`
	HandshakeTimeout  badoption.Duration           `json:"handshake_timeout,omitempty"`
	RequireEncryption bool                         `json:"require_encryption,omitempty"`
	ResponseShaping   *VMessResponseShapingOptions `json:"response_shaping,omitempty"`
}

// VMessResponseShapingOptions is server-side only; zero fields use the
// sing-vmess defaults.
type VMessResponseShapingOptions struct {
	Enabled       bool `json:"enabled,omitempty"`
	MinRecordSize int  `json:"min_record_size,omitempty"`
	MaxRecordSize int  `json:"max_record_size,omitempty"`
	MinRecords    int  `json:"min_records,omitempty"`
	MaxRecords    int  `json:"max_records,omitempty"`
}

type VMessUser struct {
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
	AlterId int    `json:"alterId,omitempty"`
}

type VMessOutboundOptions struct {
	DialerOptions
	ServerOptions
	UUID                string      `json:"uuid"`
	Security            string      `json:"security" enum:"auto,none,zero,aes-128-cfb,aes-128-gcm,chacha20-poly1305"`
	AlterId             int         `json:"alter_id,omitempty"`
	GlobalPadding       bool        `json:"global_padding,omitempty"`
	AuthenticatedLength bool        `json:"authenticated_length,omitempty"`
	Network             NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	PacketEncoding string                    `json:"packet_encoding,omitempty" enum:"packetaddr,xudp"`
	Multiplex      *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport      *V2RayTransportOptions    `json:"transport,omitempty"`
}
