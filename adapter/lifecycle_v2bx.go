package adapter

// StopChild closes the scope of a component started by this scope and forgets it,
// so the component can be removed while the parent keeps running (for v2bx).
//
// The cleanup registered by Start still references the closed child scope,
// which is harmless since closing a scope twice is a no-op.
func (s *Scope) StopChild(component Lifecycle) error {
	s.access.Lock()
	child, loaded := s.children[component]
	if loaded {
		delete(s.children, component)
	}
	s.access.Unlock()
	if !loaded {
		return nil
	}
	return child.Close()
}
