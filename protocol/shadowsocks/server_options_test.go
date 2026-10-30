package shadowsocks

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	ss "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestServerContextValidation(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings option.ShadowsocksInboundOptions
	}{
		{"negative timeout", option.ShadowsocksInboundOptions{HandshakeTimeout: -1}},
		{"excessive timeout", option.ShadowsocksInboundOptions{HandshakeTimeout: badoption.Duration(6 * time.Minute)}},
		{"record size", option.ShadowsocksInboundOptions{TrafficShaping: &option.ShadowsocksTrafficShapingOptions{Enabled: true, MinRecordSize: 32}}},
		{"record budget", option.ShadowsocksInboundOptions{TrafficShaping: &option.ShadowsocksTrafficShapingOptions{Enabled: true, MaxRecords: 65}}},
		{"UDP packet budget", option.ShadowsocksInboundOptions{UDPPadding: &option.ShadowsocksUDPPaddingOptions{Enabled: true, MaxPacketSize: 400}}},
		{"UDP padding budget", option.ShadowsocksInboundOptions{UDPPadding: &option.ShadowsocksUDPPaddingOptions{Enabled: true, MaxPaddingBytes: 901}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := serverContext(context.Background(), test.settings); err == nil {
				t.Fatal("invalid setting accepted")
			}
		})
	}
	ctx, err := serverContext(context.Background(), option.ShadowsocksInboundOptions{TrafficShaping: &option.ShadowsocksTrafficShapingOptions{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	settings := ss.ServerOptionsFromContext(ctx)
	if settings.HandshakeTimeout != 30*time.Second || !settings.TrafficShaping.Enabled || settings.TrafficShaping.MinRecordSize != 512 {
		t.Fatalf("settings were not normalized: %+v", settings)
	}
}
