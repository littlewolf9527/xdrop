// Package ifmgr manages network interface configuration for fast forward mode
package ifmgr

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

// InterfaceState stores original interface settings for restoration
type InterfaceState struct {
	Name       string
	Index      int
	WasUp      bool
	WasPromisc bool
	GRO        bool
	LRO        bool
	TSO        bool
}

// InterfaceManager manages interface configuration
type InterfaceManager struct {
	originalStates map[string]*InterfaceState
}

// NewInterfaceManager creates a new InterfaceManager
func NewInterfaceManager() *InterfaceManager {
	return &InterfaceManager{
		originalStates: make(map[string]*InterfaceState),
	}
}

// GetInterfaceIndex returns the interface index by name
func GetInterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("interface %s not found: %w", name, err)
	}
	return iface.Index, nil
}

// ConfigureInterface sets up an interface for fast forward mode
// - Brings interface UP
// - Enables promiscuous mode
// - Disables GRO, LRO, TSO offloads
func (m *InterfaceManager) ConfigureInterface(name string) error {
	// Get interface
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", name, err)
	}

	// Save original state
	state := &InterfaceState{
		Name:  name,
		Index: iface.Index,
	}

	// Check if interface is up
	state.WasUp = iface.Flags&net.FlagUp != 0

	// Check promiscuous mode (via ip link show). If the command fails we assume
	// PROMISC was NOT originally set — RestoreInterface will then disable it,
	// which is the safer default than leaving an unexpected PROMISC enabled.
	output, err := exec.Command("ip", "link", "show", name).Output()
	if err != nil {
		log.Printf("[IfMgr] Warning: failed to read initial state of %s via 'ip link show': %v (assuming promisc=off)", name, err)
		state.WasPromisc = false
	} else {
		state.WasPromisc = strings.Contains(string(output), "PROMISC")
	}

	// Check offload states
	state.GRO = m.getOffloadState(name, "generic-receive-offload")
	state.LRO = m.getOffloadState(name, "large-receive-offload")
	state.TSO = m.getOffloadState(name, "tcp-segmentation-offload")

	m.originalStates[name] = state

	// Bring interface UP
	if err := m.setInterfaceUp(name); err != nil {
		return fmt.Errorf("failed to bring %s up: %w", name, err)
	}
	log.Printf("[IfMgr] Interface %s: UP", name)

	// Enable promiscuous mode
	if err := m.setPromiscuous(name, true); err != nil {
		return fmt.Errorf("failed to set %s promiscuous: %w", name, err)
	}
	log.Printf("[IfMgr] Interface %s: promiscuous mode enabled", name)

	// Disable offloads (warnings only, don't fail)
	if err := m.setOffload(name, "gro", false); err != nil {
		log.Printf("[IfMgr] Warning: failed to disable GRO on %s: %v", name, err)
	}
	if err := m.setOffload(name, "lro", false); err != nil {
		log.Printf("[IfMgr] Warning: failed to disable LRO on %s: %v", name, err)
	}
	if err := m.setOffload(name, "tso", false); err != nil {
		log.Printf("[IfMgr] Warning: failed to disable TSO on %s: %v", name, err)
	}
	log.Printf("[IfMgr] Interface %s: offloads disabled", name)

	return nil
}

// RestoreInterface restores original interface settings
func (m *InterfaceManager) RestoreInterface(name string) error {
	state, exists := m.originalStates[name]
	if !exists {
		return nil // Nothing to restore
	}

	log.Printf("[IfMgr] Restoring interface %s...", name)

	// Restore promiscuous mode
	if !state.WasPromisc {
		if err := m.setPromiscuous(name, false); err != nil {
			log.Printf("[IfMgr] Warning: failed to disable promiscuous on %s: %v", name, err)
		}
	}

	// Restore offloads
	if state.GRO {
		if err := m.setOffload(name, "gro", true); err != nil {
			log.Printf("[IfMgr] Warning: failed to restore GRO on %s: %v", name, err)
		}
	}
	if state.LRO {
		if err := m.setOffload(name, "lro", true); err != nil {
			log.Printf("[IfMgr] Warning: failed to restore LRO on %s: %v", name, err)
		}
	}
	if state.TSO {
		if err := m.setOffload(name, "tso", true); err != nil {
			log.Printf("[IfMgr] Warning: failed to restore TSO on %s: %v", name, err)
		}
	}

	// Restore original UP/DOWN state
	// If the interface was originally DOWN, bring it back down.
	// This matters for hardware NICs where state residue after agent exit
	// can cause unexpected behavior.
	if !state.WasUp {
		if err := m.setInterfaceDown(name); err != nil {
			log.Printf("[IfMgr] Warning: failed to restore %s to DOWN state: %v", name, err)
		} else {
			log.Printf("[IfMgr] Interface %s: restored to DOWN state", name)
		}
	}

	delete(m.originalStates, name)
	log.Printf("[IfMgr] Interface %s restored", name)
	return nil
}

// RestoreAll restores all managed interfaces
func (m *InterfaceManager) RestoreAll() {
	for name := range m.originalStates {
		if err := m.RestoreInterface(name); err != nil {
			log.Printf("[IfMgr] Warning: failed to restore %s: %v", name, err)
		}
	}
}

// GetOriginalState returns the original state of an interface (for debugging)
func (m *InterfaceManager) GetOriginalState(name string) *InterfaceState {
	return m.originalStates[name]
}

// Helper: set interface UP
func (m *InterfaceManager) setInterfaceUp(name string) error {
	return exec.Command("ip", "link", "set", name, "up").Run()
}

// Helper: set interface DOWN
func (m *InterfaceManager) setInterfaceDown(name string) error {
	return exec.Command("ip", "link", "set", name, "down").Run()
}

// Helper: set promiscuous mode
func (m *InterfaceManager) setPromiscuous(name string, enable bool) error {
	mode := "off"
	if enable {
		mode = "on"
	}
	return exec.Command("ip", "link", "set", name, "promisc", mode).Run()
}

// Helper: set offload feature
func (m *InterfaceManager) setOffload(name, offload string, enable bool) error {
	mode := "off"
	if enable {
		mode = "on"
	}
	return exec.Command("ethtool", "-K", name, offload, mode).Run()
}

// Helper: get offload state
func (m *InterfaceManager) getOffloadState(name, offload string) bool {
	output, err := exec.Command("ethtool", "-k", name).Output()
	if err != nil {
		return false
	}
	// Parse output for "offload: on" or "offload: off"
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, offload+":") {
			return strings.Contains(line, ": on")
		}
	}
	return false
}
