//go:build linux

package bpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// readXDPAttachment requests one interface from the kernel in the current netns.
func readXDPAttachment(ifname string) (XDPAttachment, error) {
	var result XDPAttachment
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return result, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return result, err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return result, err
	}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3}); err != nil {
		return result, err
	}
	request := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofIfInfomsg)
	bo := binary.NativeEndian
	bo.PutUint32(request[0:4], uint32(len(request)))
	bo.PutUint16(request[4:6], unix.RTM_GETLINK)
	bo.PutUint16(request[6:8], unix.NLM_F_REQUEST)
	bo.PutUint32(request[8:12], 1)
	request[unix.NLMSG_HDRLEN] = unix.AF_UNSPEC
	bo.PutUint32(request[unix.NLMSG_HDRLEN+4:], uint32(iface.Index))
	if err = unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return result, err
	}
	buf := make([]byte, 65536)
	for {
		n, _, flags, from, err := unix.Recvmsg(fd, buf, nil, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return result, err
		}
		if flags&unix.MSG_TRUNC != 0 {
			return result, fmt.Errorf("truncated RTM_GETLINK response")
		}
		peer, ok := from.(*unix.SockaddrNetlink)
		if !ok || peer.Pid != 0 {
			return result, fmt.Errorf("RTM_GETLINK response is not from kernel")
		}
		for messages := buf[:n]; len(messages) > 0; {
			if len(messages) < unix.NLMSG_HDRLEN {
				return result, fmt.Errorf("short netlink header")
			}
			size := int(bo.Uint32(messages[:4]))
			if size < unix.NLMSG_HDRLEN || size > len(messages) {
				return result, fmt.Errorf("invalid netlink length %d", size)
			}
			message := messages[:size]
			next := (size + 3) &^ 3
			if next > len(messages) {
				next = len(messages)
			}
			messages = messages[next:]
			if bo.Uint32(message[8:12]) != 1 {
				continue
			}
			kind := bo.Uint16(message[4:6])
			payload := message[unix.NLMSG_HDRLEN:]
			if kind == unix.NLMSG_ERROR {
				if len(payload) < 4 {
					return result, fmt.Errorf("short NLMSG_ERROR")
				}
				code := int32(bo.Uint32(payload[:4]))
				if code < 0 {
					return result, unix.Errno(-code)
				}
				return result, fmt.Errorf("unexpected netlink acknowledgment without interface")
			}
			if kind == unix.NLMSG_DONE {
				return result, fmt.Errorf("interface missing from netlink response")
			}
			if kind != unix.RTM_NEWLINK {
				continue
			}
			if len(payload) < unix.SizeofIfInfomsg {
				return result, fmt.Errorf("short ifinfomsg")
			}
			if int(bo.Uint32(payload[4:8])) != iface.Index {
				continue
			}
			err = walkXDPAttributes(payload[unix.SizeofIfInfomsg:], func(kind uint16, value []byte) error {
				if kind != unix.IFLA_XDP {
					return nil
				}
				return walkXDPAttributes(value, func(kind uint16, value []byte) error {
					if kind == unix.IFLA_XDP_ATTACHED {
						if len(value) != 1 {
							return fmt.Errorf("invalid IFLA_XDP_ATTACHED size")
						}
						result.Attached = value[0]
						return nil
					}
					var dest *uint32
					switch kind {
					case unix.IFLA_XDP_PROG_ID:
						dest = &result.ProgID
					case unix.IFLA_XDP_DRV_PROG_ID:
						dest = &result.DriverID
					case unix.IFLA_XDP_SKB_PROG_ID:
						dest = &result.GenericID
					case unix.IFLA_XDP_HW_PROG_ID:
						dest = &result.OffloadID
					}
					if dest != nil {
						if len(value) != 4 {
							return fmt.Errorf("invalid XDP program ID size")
						}
						*dest = bo.Uint32(value)
					}
					return nil
				})
			})
			return result, err
		}
	}
}

func walkXDPAttributes(data []byte, visit func(uint16, []byte) error) error {
	for len(data) > 0 {
		if len(data) < 4 {
			return fmt.Errorf("short netlink attribute")
		}
		n := int(binary.NativeEndian.Uint16(data[:2]))
		if n < 4 || n > len(data) {
			return fmt.Errorf("invalid netlink attribute length %d", n)
		}
		kind := binary.NativeEndian.Uint16(data[2:4]) & 0x3fff
		if err := visit(kind, data[4:n]); err != nil {
			return err
		}
		next := (n + 3) &^ 3
		if next > len(data) {
			if n == len(data) {
				return nil
			}
			return fmt.Errorf("short netlink attribute padding")
		}
		data = data[next:]
	}
	return nil
}
