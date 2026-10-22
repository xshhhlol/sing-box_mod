package trojan

import (
	"net"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *Inbound) AddUsers(users []option.TrojanUser) error {
	h.users = append(h.users, users...)
	return h.updateUsers()
}

func (h *Inbound) DelUsers(names []string) error {
	nameMap := make(map[string]struct{}, len(names))
	for _, name := range names {
		nameMap[name] = struct{}{}
	}
	filteredUsers := make([]option.TrojanUser, 0, len(h.users))
	for _, user := range h.users {
		if _, found := nameMap[user.Name]; !found {
			filteredUsers = append(filteredUsers, user)
		}
	}
	h.users = filteredUsers
	err := h.updateUsers()
	// Close after the update: newConnection checks the user list after
	// tracking, so every connection of a deleted user is closed here or there.
	h.userconns.Range(func(key, value interface{}) bool {
		if _, found := nameMap[value.(string)]; found {
			key.(net.Conn).Close()
			h.userconns.Delete(key)
		}
		return true
	})
	return err
}

func (h *Inbound) updateUsers() error {
	return h.service.UpdateUsers(h.users, common.Map(h.users, func(user option.TrojanUser) string {
		return user.Password
	}))
}
