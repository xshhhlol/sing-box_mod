package anytls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// A null entry in fallback_for_alpn must be rejected as a config error
// instead of panicking while the inbound is created.
func TestFallbackForALPNNullEntry(t *testing.T) {
	certificate, key := testCertificate(t)
	tlsOptions := option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
		Enabled:     true,
		Certificate: []string{certificate},
		Key:         []string{key},
	}}
	fallbackForALPN := map[string]*option.ServerOptions{
		"http/1.1": {Server: "127.0.0.1", ServerPort: 8080},
		"h2":       nil,
	}
	for _, inbound := range []option.Inbound{
		{Type: C.TypeAnyTLS, Options: &option.AnyTLSInboundOptions{
			InboundTLSOptionsContainer: tlsOptions,
			FallbackForALPN:            fallbackForALPN,
		}},
		{Type: C.TypeTrojan, Options: &option.TrojanInboundOptions{
			InboundTLSOptionsContainer: tlsOptions,
			FallbackForALPN:            fallbackForALPN,
		}},
	} {
		t.Run(inbound.Type, func(t *testing.T) {
			instance, err := box.New(box.Options{
				Context: include.Context(context.Background()),
				Options: option.Options{
					Log:      &option.LogOptions{Disabled: true},
					Inbounds: []option.Inbound{inbound},
				},
			})
			if err == nil {
				instance.Close()
				t.Fatal("expected config error")
			}
			if !strings.Contains(err.Error(), "missing fallback address for ALPN h2") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func testCertificate(t *testing.T) (certificate, key string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}
