package shadowsocks

import (
	"io"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *MultiInbound) replaceUsersLocked(users []option.ShadowsocksUser) error {
	err := h.service.UpdateUsersWithPasswords(users, common.Map(users, func(user option.ShadowsocksUser) string { return user.Password }))
	if err == nil {
		h.users = users
	}
	return err
}

func (h *MultiInbound) AddUsers(users []option.ShadowsocksUser) error {
	h.usersAccess.Lock()
	next := append(append([]option.ShadowsocksUser(nil), h.users...), users...)
	err := h.replaceUsersLocked(next)
	h.usersAccess.Unlock()
	return err
}

func (h *MultiInbound) DelUsers(names []string) error {
	remove := make(map[string]struct{}, len(names))
	for _, name := range names {
		remove[name] = struct{}{}
	}
	h.usersAccess.Lock()
	next := make([]option.ShadowsocksUser, 0, len(h.users))
	for _, user := range h.users {
		if _, found := remove[user.Name]; !found {
			next = append(next, user)
		}
	}
	err := h.replaceUsersLocked(next)
	h.usersAccess.Unlock()
	if err == nil {
		h.closeRemovedConnections()
	}
	return err
}

func (h *MultiInbound) containsUser(user option.ShadowsocksUser) bool {
	if lookup, ok := h.service.(interface {
		Contains(option.ShadowsocksUser) bool
	}); ok {
		return lookup.Contains(user)
	}
	// Keep source compatibility with upstream protocol-library versions.
	h.usersAccess.RLock()
	defer h.usersAccess.RUnlock()
	for _, current := range h.users {
		if current == user {
			return true
		}
	}
	return false
}

func (h *MultiInbound) closeRemovedConnections() {
	h.userConns.Range(func(conn, user any) bool {
		if !h.containsUser(user.(option.ShadowsocksUser)) {
			conn.(io.Closer).Close()
		}
		return true
	})
}
