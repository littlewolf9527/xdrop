//go:build !linux

package bpf

import "fmt"

func readXDPAttachment(ifname string) (XDPAttachment, error) {
	return XDPAttachment{}, fmt.Errorf("XDP netlink readback is unsupported on this platform: %s", ifname)
}
