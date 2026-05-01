package service

import (
	"sync"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// TestNodeService_SnapshotIsRaceFree drives concurrent writers
// (UpdateStatus on the live nodes) against concurrent readers
// (SnapshotNodesForStats producing value copies). Run with -race; without
// the helper, the underlying *model.Node read-after-release pattern would
// trip the detector.
//
// We don't bother with a NodeClient — Stats fan-out is irrelevant to the
// race we're checking, only the shared map of *model.Node matters.
func TestNodeService_SnapshotIsRaceFree(t *testing.T) {
	svc := &NodeService{
		nodes: map[string]*model.Node{
			"n1": {ID: "n1", Name: "node-1", Endpoint: "http://10.0.0.1:8080", Status: model.NodeStatusOnline},
			"n2": {ID: "n2", Name: "node-2", Endpoint: "http://10.0.0.2:8080", Status: model.NodeStatusUnknown},
			"n3": {ID: "n3", Name: "node-3", Endpoint: "http://10.0.0.3:8080", Status: model.NodeStatusSyncing},
		},
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer: rotate node statuses
	wg.Add(1)
	go func() {
		defer wg.Done()
		statuses := []string{
			model.NodeStatusOnline, model.NodeStatusOffline,
			model.NodeStatusUnknown, model.NodeStatusSyncing,
		}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			svc.UpdateStatus("n1", statuses[i%len(statuses)])
			svc.UpdateStatus("n2", statuses[(i+1)%len(statuses)])
			svc.UpdateStatus("n3", statuses[(i+2)%len(statuses)])
			i++
		}
	}()

	// Reader: take snapshots aggressively and read every field that the
	// race-prone old code would have touched.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			snap := svc.SnapshotNodesForStats()
			for _, n := range snap {
				_ = n.ID
				_ = n.Name
				_ = n.Endpoint
				_ = n.ApiKey
				_ = n.Status
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestNodeService_SnapshotReturnsValueCopies ensures the helper returns
// values (not aliases). Mutating the returned slice must not affect the
// service's internal state, otherwise the cache could accidentally rewrite
// a live node's Status.
func TestNodeService_SnapshotReturnsValueCopies(t *testing.T) {
	svc := &NodeService{
		nodes: map[string]*model.Node{
			"n1": {ID: "n1", Name: "node-1", Endpoint: "http://10.0.0.1:8080", Status: model.NodeStatusOnline},
		},
	}
	snap := svc.SnapshotNodesForStats()
	if len(snap) != 1 {
		t.Fatalf("expected 1 node, got %d", len(snap))
	}
	snap[0].Status = "GARBAGE"
	snap[0].Endpoint = "http://corrupted"

	again := svc.SnapshotNodesForStats()
	if again[0].Status != model.NodeStatusOnline {
		t.Fatalf("snapshot mutation leaked back into service: status=%s", again[0].Status)
	}
	if again[0].Endpoint != "http://10.0.0.1:8080" {
		t.Fatalf("snapshot mutation leaked endpoint: %s", again[0].Endpoint)
	}
}
