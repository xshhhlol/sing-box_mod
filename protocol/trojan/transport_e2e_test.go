package trojan_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func freePort(t *testing.T) uint16 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func selfSigned(t *testing.T) (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.org"}, DNSNames: []string{"example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func echoServer(t *testing.T) uint16 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func loopback() *badoption.Addr {
	return common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1")))
}

func tlsInbound(cert, key string) option.InboundTLSOptionsContainer {
	return option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
		Enabled: true, ServerName: "example.org", Certificate: badoption.Listable[string]{cert}, Key: badoption.Listable[string]{key}}}
}

func startBox(t *testing.T, options option.Options) {
	t.Helper()
	options.Log = &option.LogOptions{Level: "error"}
	instance, err := box.New(box.Options{Context: include.Context(context.Background()), Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
}

// for v2bx: Trojan through every V2Ray transport, end to end. WebSocket, gRPC
// and HTTP/2 connections cannot set read deadlines; the handshake deadline
// once refused all of them.
func TestE2ETrojanTransports(t *testing.T) {
	cert, key := selfSigned(t)
	echo := echoServer(t)
	for _, transport := range []*option.V2RayTransportOptions{
		nil,
		{Type: C.V2RayTransportTypeWebsocket},
		{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: option.V2RayWebsocketOptions{MaxEarlyData: 2048}},
		{Type: C.V2RayTransportTypeGRPC},
		{Type: C.V2RayTransportTypeHTTP},
		{Type: C.V2RayTransportTypeHTTPUpgrade},
	} {
		name := "tcp"
		if transport != nil {
			name = transport.Type
			if transport.WebsocketOptions.MaxEarlyData > 0 {
				name += "-early"
			}
		}
		t.Run(name, func(t *testing.T) {
			serverPort, clientPort := freePort(t), freePort(t)
			startBox(t, option.Options{
				Inbounds: []option.Inbound{
					{Type: C.TypeMixed, Tag: "mixed-in", Options: &option.HTTPMixedInboundOptions{ListenOptions: option.ListenOptions{
						Listen: loopback(), ListenPort: clientPort}}},
					{Type: C.TypeTrojan, Tag: "trojan-in", Options: &option.TrojanInboundOptions{
						ListenOptions:              option.ListenOptions{Listen: loopback(), ListenPort: serverPort},
						Users:                      []option.TrojanUser{{Name: "u", Password: "password"}},
						InboundTLSOptionsContainer: tlsInbound(cert, key),
						Transport:                  transport,
					}},
				},
				Outbounds: []option.Outbound{
					{Type: C.TypeDirect, Tag: "direct"},
					{Type: C.TypeTrojan, Tag: "trojan-out", Options: &option.TrojanOutboundOptions{
						ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: serverPort},
						Password:      "password",
						OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
							Enabled: true, ServerName: "example.org", Insecure: true}},
						Transport: transport,
					}},
				},
				Route: &option.RouteOptions{Rules: []option.Rule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{Inbound: []string{"mixed-in"}},
					RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "trojan-out"}},
				}}}},
			})
			client := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
			for i := 0; i < 3; i++ {
				conn, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:"+strconv.Itoa(int(echo))))
				if err != nil {
					t.Fatal(err)
				}
				payload := bytes.Repeat([]byte("ping"), 1000)
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				go conn.Write(payload)
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("echo through trojan: %v", err)
				}
				conn.Close()
			}
		})
	}
}

// for v2bx: web requests reach the fallback site through the real relay,
// whether the request head arrives in the first read or in pieces, and the
// connection stays usable for keep-alive requests.
func TestE2ETrojanFallback(t *testing.T) {
	cert, key := selfSigned(t)
	site, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("site"))
	}), ReadHeaderTimeout: 30 * time.Second}
	go server.Serve(site)
	t.Cleanup(func() { server.Close() })
	serverPort := freePort(t)
	startBox(t, option.Options{
		Inbounds: []option.Inbound{{Type: C.TypeTrojan, Tag: "trojan-in", Options: &option.TrojanInboundOptions{
			ListenOptions:              option.ListenOptions{Listen: loopback(), ListenPort: serverPort},
			Users:                      []option.TrojanUser{{Name: "u", Password: "password"}},
			InboundTLSOptionsContainer: tlsInbound(cert, key),
			Fallback:                   &option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(site.Addr().(*net.TCPAddr).Port)},
		}}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
	})
	for _, test := range []struct {
		name   string
		chunks []string
		status int
	}{
		{"whole request", []string{"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"}, 200},
		{"fragmented request", []string{"GET /", " HTTP/1.1\r\nHost: exam", "ple.org\r\n\r\n"}, 200},
		{"hex then text", []string{"abc", " / HTTP/1.1\r\nHost: example.org\r\n\r\n"}, 200},
		{"malformed", []string{"0123", "X\r\n\r\n"}, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, err := stdtls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(serverPort)), &stdtls.Config{
				ServerName: "example.org", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			for _, chunk := range test.chunks {
				if _, err := conn.Write([]byte(chunk)); err != nil {
					t.Fatal(err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status %d, want %d", response.StatusCode, test.status)
			}
			if test.status != 200 {
				return
			}
			conn.Write([]byte("GET /again HTTP/1.1\r\nHost: example.org\r\n\r\n"))
			response, err = http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal("keep-alive request: ", err)
			}
			response.Body.Close()
		})
	}
}
