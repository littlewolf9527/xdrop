package rules

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type ruleAuditView struct {
	ID        string           `json:"id"`
	LogicalID int64            `json:"logical_id"`
	Match     store.Match      `json:"match"`
	Enabled   bool             `json:"enabled"`
	Comment   string           `json:"comment"`
	ExpiresAt *string          `json:"expires_at"`
	CreatedBy string           `json:"created_by"`
	UpdatedBy string           `json:"updated_by"`
	Claimants []store.ClaimRow `json:"claimants"`
}

func ruleView(tx *sql.Tx, id string) (*ruleAuditView, error) {
	r, err := store.Get(tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	claims, err := store.Claims(tx, id)
	return &ruleAuditView{r.ID, r.LogicalID, r.Match, r.Enabled, r.Comment, r.ExpiresAt, r.CreatedBy, r.UpdatedBy, claims}, err
}

type whitelistAuditView struct {
	ID       string `json:"id"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
	Comment  string `json:"comment"`
}

func whitelistView(w store.Whitelist) whitelistAuditView {
	return whitelistAuditView{w.ID, w.SrcIP, w.DstIP, w.SrcPort, w.DstPort, w.Protocol, w.Comment}
}
func record(tx *sql.Tx, a Actor, action, target string, before, after any, at string) error {
	b, err := json.Marshal(before)
	if err != nil {
		return err
	}
	c, err := json.Marshal(after)
	if err != nil {
		return err
	}
	if action == "rule.update" && bytes.Equal(b, c) {
		return nil
	}
	if string(b) == "null" {
		b = nil
	}
	if string(c) == "null" {
		c = nil
	}
	return store.InsertAudit(tx, store.AuditEvent{At: at, Actor: a.Who(), Source: a.Source, Action: action, Target: target, Before: b, After: c})
}
func recordRule(tx *sql.Tx, a Actor, action, id, at string, before *ruleAuditView) error {
	after, err := ruleView(tx, id)
	if err != nil {
		return err
	}
	return record(tx, a, action, "rule:"+id, before, after, at)
}
func ruleChange(tx *sql.Tx, a Actor, action, id, at string, write func() error) error {
	before, err := ruleView(tx, id)
	if err != nil {
		return err
	}
	if err := write(); err != nil {
		return err
	}
	return recordRule(tx, a, action, id, at, before)
}
func (s *Service) Record(a Actor, action, target string) *Error {
	return auditError(s.transaction(func(tx *sql.Tx) error {
		return record(tx, a, action, target, nil, nil, s.now().UTC().Format(timeFormat))
	}))
}
func (s *Service) auditQueryer() store.Queryer {
	if s.auditReader != nil {
		return s.auditReader
	}
	return s.db.Reader()
}
func (s *Service) AuditPage(from, to, at string, id int64, limit int) ([]store.AuditEvent, *Error) {
	return s.AuditPageAction("", from, to, at, id, limit)
}
func (s *Service) AuditPageAction(action, from, to, at string, id int64, limit int) ([]store.AuditEvent, *Error) {
	rows, err := store.AuditPageAction(s.auditQueryer(), action, from, to, at, id, limit)
	return rows, auditError(err)
}
func (s *Service) AuditExport(from, to string, emit func(store.AuditEvent) error) error {
	return s.AuditExportAction("", from, to, emit)
}
func (s *Service) AuditExportAction(action, from, to string, emit func(store.AuditEvent) error) error {
	at, id := "", int64(0)
	for {
		rows, err := store.AuditAfterAction(s.auditQueryer(), action, from, to, at, id, 1000)
		if err != nil {
			return err
		}
		for _, e := range rows {
			if err := emit(e); err != nil {
				return err
			}
			at, id = e.At, e.ID
		}
		if len(rows) < 1000 {
			return nil
		}
	}
}

const auditPurgeBatch = 5000

func (s *Service) purgeAudit(now time.Time) *Error {
	if s.beforePurge != nil {
		s.beforePurge()
	}
	settings, err := store.ReadSettings(s.db.Reader())
	if err != nil {
		return internal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return internal(err)
	}
	defer tx.Rollback()
	if _, err := store.PurgeAudit(tx, now.Add(-time.Duration(settings.AuditRetentionDays)*24*time.Hour).UTC().Format(timeFormat), auditPurgeBatch); err != nil {
		return internal(err)
	}
	return auditError(tx.Commit())
}

func auditError(err error) *Error {
	if err == nil {
		return nil
	}
	return internal(err)
}
