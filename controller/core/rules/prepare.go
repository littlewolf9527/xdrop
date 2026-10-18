package rules

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type Violation struct{ ID, Reason string }
type Report struct {
	Violations []Violation
	ledger     *ledger
	ledgerTime time.Duration
}

func Prepare(db *store.DB) (Report, error) {
	return prepare(db, BuiltinLimits().Values)
}
func prepare(db *store.DB, limits Values) (Report, error) {
	report := Report{Violations: []Violation{}}
	if err := db.Migrate(); err != nil {
		return report, err
	}
	rows, err := store.List(db)
	if err != nil {
		return report, err
	}
	add := func(id, reason string) { report.Violations = append(report.Violations, Violation{id, reason}) }
	for _, r := range rows {
		c, e := Canonicalize(r.Match)
		if e != nil {
			add(r.ID, e.Error())
			continue
		}
		if !reflect.DeepEqual(r.Match, c.RuleInput) || r.Kind != c.Kind || r.GroupKey != c.GroupKey || r.CondKey != c.CondKey {
			add(r.ID, "stored canonical form or identity differs")
		}
	}
	wls, err := store.ListWhitelist(db)
	if err != nil {
		return report, err
	}
	started := time.Now()
	report.ledger, _ = buildLedger(rows, len(wls))
	report.ledgerTime = time.Since(started)
	for _, e := range ledgerConstraints(report.ledger, limits) {
		if len(e.RuleIDs) == 0 {
			add("capacity:"+e.Table, e.Error())
		}
		for _, id := range e.RuleIDs {
			add(id, e.Error())
		}
	}
	for _, w := range wls {
		in := WhitelistInput{SrcIP: w.SrcIP, DstIP: w.DstIP, SrcPort: w.SrcPort, DstPort: w.DstPort, Protocol: w.Protocol, Comment: w.Comment}
		c, e := CanonicalizeWhitelist(in)
		if e != nil {
			add(w.ID, e.Error())
			continue
		}
		if c.WhitelistInput != in || c.Key != w.Key {
			add(w.ID, "stored whitelist canonical form or identity differs")
		}
	}
	sort.Slice(report.Violations, func(i, j int) bool {
		a, b := report.Violations[i], report.Violations[j]
		if a.ID == b.ID {
			return a.Reason < b.Reason
		}
		return a.ID < b.ID
	})
	return report, nil
}

// DryRun checks a byte copy of a cold database. The source controller must be
// stopped: copying the files of an active database is not a consistent snapshot.
func DryRun(path string, out io.Writer) int {
	errCode := func(err error) int { fmt.Fprintln(out, err); return 2 }
	dir, err := os.MkdirTemp("", "ctlcut1-dryrun-")
	if err != nil {
		return errCode(err)
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, "database.sqlite")
	for _, suffix := range []string{"", "-journal", "-wal"} {
		bytes, err := os.ReadFile(path + suffix)
		if suffix != "" && os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return errCode(err)
		}
		if err = os.WriteFile(copyPath+suffix, bytes, 0600); err != nil {
			return errCode(err)
		}
	}
	db, err := store.Open(copyPath)
	if err != nil {
		return errCode(err)
	}
	defer db.Close()
	report, err := Prepare(db)
	if err != nil {
		return errCode(err)
	}
	for _, v := range report.Violations {
		fmt.Fprintf(out, "%s\t%s\n", v.ID, v.Reason)
	}
	if len(report.Violations) > 0 {
		return 1
	}
	return 0
}
