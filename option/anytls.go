package option

import "github.com/sagernet/sing/common/json/badoption"

type AnyTLSInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users            []AnyTLSUser                 `json:"users,omitempty"`
	PaddingScheme    badoption.Listable[string]   `json:"padding_scheme,omitempty"`
	TrafficShaping   *AnyTLSTrafficShapingOptions `json:"traffic_shaping,omitempty"`
	HandshakeTimeout badoption.Duration           `json:"handshake_timeout,omitempty"`
	Fallback         *ServerOptions               `json:"fallback,omitempty"`
	FallbackForALPN  map[string]*ServerOptions    `json:"fallback_for_alpn,omitempty"`
}

type AnyTLSTrafficShapingOptions struct {
	Enabled         bool `json:"enabled,omitempty"`
	MinRecordSize   int  `json:"min_record_size,omitempty"`
	MaxRecordSize   int  `json:"max_record_size,omitempty"`
	MinRecords      int  `json:"min_records,omitempty"`
	MaxRecords      int  `json:"max_records,omitempty"`
	MaxPaddingBytes int  `json:"max_padding_bytes,omitempty"`
}

type AnyTLSUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type AnyTLSOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Password                 string             `json:"password,omitempty"`
	IdleSessionCheckInterval badoption.Duration `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       badoption.Duration `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int                `json:"min_idle_session,omitempty"`
	ClientMetadata           string             `json:"client_metadata,omitempty"`
}
