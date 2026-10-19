package bpf

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestIPv6ParserTextParity(t *testing.T) {
	paths := []string{"../../bpf/xdrop_main.c", "../../bpf/xdrop_gate.c"}
	var bodies [2]string
	var definitions [2]int
	start := regexp.MustCompile(`(?m)^static INLINE __u8 parse_ipv6_nexthdr\(`)
	for i, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		matches := start.FindAllIndex(raw, -1)
		definitions[i] = len(matches)
		if len(matches) == 1 {
			body := string(raw[matches[0][0]:])
			end := strings.Index(body, "\n}")
			if end < 0 {
				t.Fatalf("parser closing brace missing: %s", path)
			}
			bodies[i] = body[:end+2]
		}
	}
	t.Logf("parser definitions main %d / gate %d", definitions[0], definitions[1])
	if definitions != [2]int{1, 1} {
		t.Fatalf("parser definition count: main %d / gate %d", definitions[0], definitions[1])
	}
	if bodies[0] == bodies[1] {
		return
	}
	main, gate := strings.Split(bodies[0], "\n"), strings.Split(bodies[1], "\n")
	for i := 0; i < max(len(main), len(gate)); i++ {
		a, b := "<EOF>", "<EOF>"
		if i < len(main) {
			a = main[i]
		}
		if i < len(gate) {
			b = gate[i]
		}
		if a != b {
			t.Fatalf("parser text unequal at function line %d\nmain: %s\ngate: %s", i+1, a, b)
		}
	}
}
