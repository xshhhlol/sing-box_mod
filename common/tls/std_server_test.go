package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestSTDServerRejectUnknownSNI(t *testing.T) {
	certificate, key := generateTestCertificate(t, "*.node.example.com")
	newServer := func(t *testing.T, serverName string, reject bool) ServerConfig {
		t.Helper()
		config, err := NewSTDServer(context.Background(), log.NewNOPFactory().Logger(), option.InboundTLSOptions{
			Enabled:          true,
			ServerName:       serverName,
			Certificate:      []string{certificate},
			Key:              []string{key},
			RejectUnknownSNI: reject,
		})
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	handshake := func(server ServerConfig, serverName string) error {
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() {
			if conn, err := ServerHandshake(ctx, serverConn, server); err == nil {
				conn.Close()
			} else {
				serverConn.Close()
			}
		}()
		return tls.Client(clientConn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).HandshakeContext(ctx)
	}

	server := newServer(t, "panel.example.net", true)
	for _, serverName := range []string{"panel.example.net", "PANEL.example.net", "a.node.example.com"} {
		if err := handshake(server, serverName); err != nil {
			t.Errorf("known SNI %q rejected: %v", serverName, err)
		}
	}
	for _, serverName := range []string{"", "random.example.org", "node.example.com", "a.b.node.example.com"} {
		err := handshake(server, serverName)
		if err == nil || !strings.Contains(err.Error(), "unrecognized name") {
			t.Errorf("unknown SNI %q: got %v, want unrecognized name alert", serverName, err)
		}
	}
	if err := handshake(newServer(t, "", true), "a.node.example.com"); err != nil {
		t.Errorf("certificate name rejected without server_name: %v", err)
	}
	if err := handshake(newServer(t, "panel.example.net", false), "random.example.org"); err != nil {
		t.Errorf("SNI rejected with reject_unknown_sni disabled: %v", err)
	}
}

func generateTestCertificate(t *testing.T, dnsName string) (certificatePEM, keyPEM string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
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
