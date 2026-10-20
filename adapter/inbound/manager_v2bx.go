package inbound

import (
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

// Hot add and remove of inbounds, removed upstream but required by v2bx.

func inboundName(inbound adapter.Inbound) string {
	return "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
}

// startInbound runs all start stages for an inbound created after the manager started.
// Must be called with m.access held.
func (m *Manager) startInbound(inbound adapter.Inbound) error {
	for _, stage := range adapter.ListStartStages {
		err := m.scope.Start(inboundName(inbound), inbound, stage)
		if err != nil {
			return E.Errors(err, m.scope.StopChild(inbound))
		}
	}
	return nil
}

// removeInbound must be called with m.access held.
func (m *Manager) removeInbound(inbound adapter.Inbound) error {
	delete(m.inboundByTag, inbound.Tag())
	m.inbounds = common.Filter(m.inbounds, func(it adapter.Inbound) bool {
		return it != inbound
	})
	if m.started {
		return m.scope.StopChild(inbound)
	}
	return nil
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	defer m.access.Unlock()
	inbound, found := m.inboundByTag[tag]
	if !found {
		return os.ErrInvalid
	}
	return m.removeInbound(inbound)
}
