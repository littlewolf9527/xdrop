package rules

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCtlCut3ReadPool(t *testing.T) {
	t.Run("RP-readpool", func(t *testing.T) {
		s, _ := setup(t)
		r := create(t, s, draft(80, ""))
		w, e := s.CreateWhitelist(ui, WhitelistInput{DstIP: "192.0.2.10"})
		if e != nil {
			t.Fatal(e)
		}
		arrived, release, done := make(chan struct{}), make(chan struct{}), make(chan *Error, 1)
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		s.beforeCommit = func(*sql.Tx) error {
			close(arrived)
			select {
			case <-release:
				return nil
			case <-time.After(10 * time.Second):
				return fmt.Errorf("bounded fixture release expired")
			}
		}
		go func() { _, err := s.Create(ui, "", draft(81, "")); done <- err }()
		t.Cleanup(func() {
			unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("writer did not finish")
			}
		})
		select {
		case <-arrived:
		case <-time.After(2 * time.Second):
			t.Fatal("writer never reached beforeCommit")
		}
		reads := []struct {
			name string
			read func() bool
		}{
			{"Get", func() bool { got, e := s.Get(r.ID); return e == nil && got.ID == r.ID }},
			{"List", func() bool { got, e := s.List(); return e == nil && len(got) == 1 && got[0].ID == r.ID }},
			{"ListPage", func() bool { got, e := s.ListPage(0, 10); return e == nil && len(got) == 1 && got[0].ID == r.ID }},
			{"ListEnabledByGroup", func() bool {
				got, e := s.ListEnabledByGroup(r.GroupKey)
				return e == nil && len(got) == 1 && got[0].ID == r.ID
			}},
			{"ListWhitelist", func() bool {
				got, e := s.ListWhitelist()
				return e == nil && len(got) == 1 && got[0].ID == w.Whitelist.ID
			}},
			{"ListWhitelistPage", func() bool {
				got, e := s.ListWhitelistPage("", 10)
				return e == nil && len(got) == 1 && got[0].ID == w.Whitelist.ID
			}},
		}
		for _, read := range reads {
			read := read
			returned := make(chan bool, 1)
			go func() { returned <- read.read() }()
			select {
			case ok := <-returned:
				if !ok {
					t.Errorf("%s did not see committed content", read.name)
				}
			case <-time.After(2 * time.Second):
				t.Errorf("%s waited for write pool", read.name)
			}
		}
		unblock()
	})
}
