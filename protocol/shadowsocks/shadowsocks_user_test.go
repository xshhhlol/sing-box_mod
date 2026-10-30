package shadowsocks

import (
	"bytes"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
)

func TestFailedUserUpdateKeepsActiveUsers(t *testing.T) {
	s, err := shadowaead_2022.NewMultiService[option.ShadowsocksUser]("2022-blake3-aes-128-gcm", bytes.Repeat([]byte{1}, 16), 300, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &MultiInbound{service: s}
	valid := option.ShadowsocksUser{Name: "valid", Password: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))}
	if err = h.AddUsers([]option.ShadowsocksUser{valid}); err != nil {
		t.Fatal(err)
	}
	if err = h.AddUsers([]option.ShadowsocksUser{{Name: "bad", Password: "invalid-base64"}}); err == nil {
		t.Fatal("invalid PSK accepted")
	}
	if len(h.users) != 1 || h.users[0] != valid || !h.containsUser(valid) {
		t.Fatal("failed update changed the active users")
	}
	if err = h.UpdateUsers([]string{"bad"}, nil); err == nil || !h.containsUser(valid) {
		t.Fatal("mismatched update changed the active users")
	}
}

func TestConcurrentUserChangesKeepStableIdentity(t *testing.T) {
	s, err := shadowaead.NewMultiService[option.ShadowsocksUser]("aes-128-gcm", 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &MultiInbound{service: s}
	keep := option.ShadowsocksUser{Name: "keep", Password: "keep-password"}
	if err = h.AddUsers([]option.ShadowsocksUser{keep}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			user := option.ShadowsocksUser{Name: string(rune('a' + i)), Password: "test-password"}
			if err := h.AddUsers([]option.ShadowsocksUser{user}); err != nil {
				t.Error(err)
			}
			if err := h.DelUsers([]string{user.Name}); err != nil {
				t.Error(err)
			}
			if !h.containsUser(keep) {
				t.Error("surviving user's identity changed")
			}
		}(i)
	}
	wg.Wait()
	if len(h.users) != 1 || h.users[0] != keep {
		t.Fatalf("unexpected active users: %d", len(h.users))
	}
}
