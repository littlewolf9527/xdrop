package nodeclient

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func TestCapacityProtocol(t *testing.T) {
	t.Run("NC-probe11", func(t *testing.T) {
		for _, protocol := range []int{11, 10, 12} {
			protocol := protocol
			c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "{\"sync_protocol\":%d}", protocol)
			}), Options{})
			got, err := c.Probe(context.Background())
			want := Incompatible
			if protocol == 11 {
				want = OK
			}
			if err != nil || got != want {
				t.Fatalf("protocol=%d got=%v err=%v want=%v", protocol, got, err, want)
			}
		}
	})
}
