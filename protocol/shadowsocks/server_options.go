package shadowsocks

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/option"
	ss "github.com/sagernet/sing-shadowsocks"
)

func serverContext(ctx context.Context, options option.ShadowsocksInboundOptions) (context.Context, error) {
	settings := ss.ServerOptions{HandshakeTimeout: time.Duration(options.HandshakeTimeout)}
	if shaping := options.TrafficShaping; shaping != nil {
		settings.TrafficShaping = ss.TrafficShapingOptions{
			Enabled: shaping.Enabled, MinRecordSize: shaping.MinRecordSize,
			MaxRecordSize: shaping.MaxRecordSize, MinRecords: shaping.MinRecords, MaxRecords: shaping.MaxRecords,
		}
	}
	if padding := options.UDPPadding; padding != nil {
		settings.UDPPadding = ss.UDPPaddingOptions{Enabled: padding.Enabled, MaxPacketSize: padding.MaxPacketSize, MaxPaddingBytes: padding.MaxPaddingBytes}
	}
	return ss.WithServerOptions(ctx, settings)
}
