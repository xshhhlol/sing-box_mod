package vmess

import (
	"net"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *Inbound) AddUsers(users []option.VMessUser) error {
	h.users = append(h.users, users...)
	return h.updateUsers()
}

func (h *Inbound) DelUsers(uuids []string) error {
	toDelete := make(map[string]struct{}, len(uuids))
	for _, uuid := range uuids {
		toDelete[uuid] = struct{}{}
	}
	remaining := make([]option.VMessUser, 0, len(h.users))
	for _, user := range h.users {
		if _, found := toDelete[user.Name]; !found {
			remaining = append(remaining, user)
		}
	}
	h.users = remaining
	err := h.updateUsers()
	// for v2bx: close after the update: newConnectionEx checks the user list
	// after tracking, so every connection of a deleted user is closed here or
	// there.
	h.userconns.Range(func(key, value interface{}) bool {
		if _, found := toDelete[value.(string)]; found {
			key.(net.Conn).Close()
			h.userconns.Delete(key)
		}
		return true
	})
	return err
}

func (h *Inbound) updateUsers() error {
	return h.service.UpdateUsers(h.users, common.Map(h.users, func(it option.VMessUser) string {
		return it.UUID
	}), common.Map(h.users, func(it option.VMessUser) int {
		return it.AlterId
	}))
}
