package rules

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type ActorKind string

const (
	UI      ActorKind = "ui"
	Machine ActorKind = "machine"
	System  ActorKind = "system"
)

type Actor struct {
	Kind   ActorKind
	Name   string
	Source string
	Admin  bool
}

func (a Actor) String() string {
	if a.Kind == UI {
		return "ui"
	}
	return "cred:" + a.Name
}

func (a Actor) Who() string {
	return map[ActorKind]string{UI: "user:", Machine: "cred:", System: "system:"}[a.Kind] + a.Name
}

type Move struct{ RuleID, OldKey, NewKey string }
type Change struct {
	Gen       uint64
	RuleKeys  []string
	Moves     []Move
	Whitelist bool
}
type ChangeSink interface{ Changed(Change) }
type Result struct {
	Rule     store.Rule
	Existing bool
	Gen      uint64
}
type BatchResult struct {
	Index int
	Result
	Error *Error
}
type WLResult struct {
	Whitelist store.Whitelist
	Existing  bool
}

type Service struct {
	db           *store.DB
	mu           sync.Mutex
	gen          uint64
	commitSeq    uint64
	renewed      bool
	epoch        string
	keyGen       map[string]uint64
	status       func() []DeliveryNode
	sink         ChangeSink
	now          func() time.Time
	Now          func() time.Time
	trieLimit    int
	ledger       *ledger
	limits       func() Limits
	writeLimits  Limits
	reserve      int
	beforeInsert func(store.Rule) error
	beforeCommit func(*sql.Tx) error
	beforePurge  func()
	auditReader  store.Queryer
}

func New(db *store.DB, sink ChangeSink, status ...func() []DeliveryNode) *Service {
	epoch, err := newID("")
	if err != nil {
		panic(err)
	}
	s := &Service{db: db, sink: sink, now: time.Now, trieLimit: TrieLimit, reserve: DefaultLogicalReserve, epoch: epoch, keyGen: map[string]uint64{}}
	s.Now = time.Now
	s.now = func() time.Time { return s.Now() }
	if len(status) > 0 {
		s.status = status[0]
	}
	return s
}

type DeliveryRejection struct {
	Key, ID, Code, Error string
	RuleIDs              []string
}
type DeliveryNode struct {
	Name                                      string
	Online, Incompatible, Confirmable, Synced bool
	Overloaded                                bool
	ConfirmedGen                              uint64
	Rejected                                  []DeliveryRejection
}

func (s *Service) Epoch() string { return s.epoch }

func (s *Service) Revision() (uint64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitSeq, s.gen
}

// DeliveryView pairs the current target with one status snapshot under the
// existing service-to-sink lock order. The callback must not call the service.
func (s *Service) DeliveryView(id string) (store.Rule, uint64, []DeliveryNode, *Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := store.Get(s.db, id)
	if err != nil {
		return r, 0, nil, missing(err)
	}
	nodes := []DeliveryNode{}
	if s.status != nil {
		nodes = s.status()
	}
	return r, s.keyGen[r.GroupKey], nodes, nil
}

func newID(prefix string) (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(bytes[:]), nil
}
func missing(err error) *Error {
	if errors.Is(err, sql.ErrNoRows) {
		return &Error{Code: "not_found", Message: "rule not found"}
	}
	return internal(err)
}
func conflict(id string) *Error {
	return &Error{Code: "rule_conflict", RuleID: id, Message: "rule identity is occupied"}
}

func (s *Service) withWrite(f func(*Change) *Error) *Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	change := Change{}
	if e := s.ensureLedger(); e != nil {
		return e
	}
	s.writeLimits = s.currentLimits()
	if err := f(&change); err != nil {
		return err
	}
	s.notify(change)
	return nil
}
func (s *Service) notify(c Change) {
	if s.renewed || len(c.RuleKeys) != 0 || c.Whitelist {
		s.commitSeq++
	}
	s.renewed = false
	if len(c.RuleKeys) == 0 && !c.Whitelist {
		return
	}
	keys := map[string]bool{}
	for _, k := range c.RuleKeys {
		keys[k] = true
	}
	c.RuleKeys = nil
	for k := range keys {
		c.RuleKeys = append(c.RuleKeys, k)
	}
	sort.Strings(c.RuleKeys)
	s.gen++
	c.Gen = s.gen
	for _, key := range c.RuleKeys {
		s.keyGen[key] = c.Gen
	}
	if s.sink != nil {
		s.sink.Changed(c)
	}
}
func (s *Service) transaction(f func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = f(tx); err != nil {
		return err
	}
	if s.beforeCommit != nil {
		if err = s.beforeCommit(tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func claimRefFor(a Actor, ref string) string {
	if a.Kind == UI {
		return ""
	}
	return ref
}
func existingResult(r, proposed store.Rule) (Result, *Error) {
	if r.Action != proposed.Action || r.RateLimit != proposed.RateLimit {
		return Result{}, conflict(r.ID)
	}
	if r.ExpiresAt != nil && (proposed.ExpiresAt == nil || *proposed.ExpiresAt > *r.ExpiresAt) {
		r.ExpiresAt = proposed.ExpiresAt
	}
	return Result{Rule: r, Existing: true}, nil
}
func (s *Service) existing(a Actor, ref string, r, proposed store.Rule) (Result, *Error) {
	result, e := existingResult(r, proposed)
	if e != nil {
		return Result{}, e
	}
	renewed := r.ExpiresAt != result.Rule.ExpiresAt
	err := s.transaction(func(tx *sql.Tx) error {
		before, err := ruleView(tx, r.ID)
		if err != nil {
			return err
		}
		if r.ExpiresAt != result.Rule.ExpiresAt {
			r = result.Rule
			if err := store.UpdateRule(tx, r); err != nil {
				return err
			}
		}
		at := s.now().UTC().Format(timeFormat)
		added, err := store.AddClaim(tx, r.ID, a.String(), claimRefFor(a, ref), at)
		if err != nil || !added {
			return err
		}
		return recordRule(tx, a, "rule.claim", r.ID, at, before)
	})
	if err != nil {
		return Result{}, internal(err)
	}
	s.renewed = s.renewed || renewed
	return result, nil
}
func canonicalRow(r *store.Rule, c Canon) {
	r.Match = c.RuleInput
	r.Kind = c.Kind
	r.GroupKey = c.GroupKey
	r.CondKey = c.CondKey
}

func (s *Service) create(a Actor, ref string, p RulePatch, change *Change, candidateRef string) (Result, *Error) {
	if a.Kind == System {
		return Result{}, &Error{Code: "forbidden", Message: "system cannot claim rules"}
	}
	now := s.now()
	r := store.Rule{Enabled: true, CreatedAt: now.UTC().Format(timeFormat), UpdatedAt: now.UTC().Format(timeFormat), CreatedBy: a.Who(), UpdatedBy: a.Who()}
	if e := applyPatch(&r, p, true, now); e != nil {
		return Result{}, e
	}
	c, e := Canonicalize(r.Match)
	if e != nil {
		return Result{}, e
	}
	canonicalRow(&r, c)
	old, err := store.Identity(s.db, r.GroupKey, r.CondKey)
	if err == nil {
		return s.existing(a, ref, old, r)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Result{}, internal(err)
	}
	r.ID, err = newID("rule_")
	if err != nil {
		return Result{}, internal(err)
	}
	if e = s.admitWith(s.ledger, r, store.Rule{}); e != nil {
		ids := e.RuleIDs[:0]
		for _, id := range e.RuleIDs {
			if id == r.ID {
				id = candidateRef
			}
			if id != "" {
				ids = append(ids, id)
			}
		}
		e.RuleIDs = ids
		return Result{}, e
	}
	if s.beforeInsert != nil {
		if err = s.beforeInsert(r); err != nil {
			return Result{}, internal(err)
		}
	}
	err = s.transaction(func(tx *sql.Tx) error {
		var err error
		r.LogicalID, err = store.NextLogicalID(tx)
		if err != nil {
			return err
		}
		if err = store.InsertRule(tx, r); err != nil {
			return err
		}
		if err := store.Claim(tx, r.ID, a.String(), claimRefFor(a, ref), r.CreatedAt); err != nil {
			return err
		}
		return recordRule(tx, a, "rule.create", r.ID, r.CreatedAt, nil)
	})
	if store.Unique(err) {
		old, readErr := store.Identity(s.db, r.GroupKey, r.CondKey)
		if readErr == nil {
			return s.existing(a, ref, old, r)
		}
	}
	if errors.Is(err, store.ErrLogicalFull) {
		return Result{}, &Error{Code: "table_full", Table: "logical_id", Message: err.Error()}
	}
	if err != nil {
		return Result{}, internal(err)
	}
	s.ledger.change(r, 1)
	change.RuleKeys = append(change.RuleKeys, r.GroupKey)
	return Result{Rule: r}, nil
}

func (s *Service) Create(a Actor, ref string, p RulePatch) (result Result, e *Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Change{}
	if e = s.ensureLedger(); e != nil {
		return
	}
	s.writeLimits = s.currentLimits()
	result, e = s.create(a, ref, p, &c, "")
	if e == nil {
		s.notify(c)
		result.Gen = s.keyGen[result.Rule.GroupKey]
	}
	return
}
func (s *Service) BatchCreate(a Actor, ref string, items []RulePatch) []BatchResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	results := make([]BatchResult, len(items))
	c := Change{}
	e := s.ensureLedger()
	s.writeLimits = s.currentLimits()
	for i, p := range items {
		if e != nil {
			results[i].Index, results[i].Error = i, e
			continue
		}
		results[i].Index = i
		results[i].Result, results[i].Error = s.create(a, ref, p, &c, "batch:"+strconv.Itoa(i))
	}
	s.notify(c)
	for i := range results {
		if results[i].Error == nil {
			results[i].Gen = s.keyGen[results[i].Rule.GroupKey]
		}
	}
	return results
}
func (s *Service) BatchValidate(a Actor, items []RulePatch) []BatchResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.ensureLedger()
	s.writeLimits = s.currentLimits()
	results := make([]BatchResult, len(items))
	if e != nil {
		for i := range results {
			results[i].Index, results[i].Error = i, e
		}
		return results
	}
	l := s.ledger.clone()
	high, err := store.LogicalHighWater(s.db.Reader())
	seen, refs := map[string]store.Rule{}, map[string]string{}
	for i, p := range items {
		result, fail := func() (Result, *Error) {
			if err != nil {
				return Result{}, internal(err)
			}
			if a.Kind == System {
				return Result{}, &Error{Code: "forbidden", Message: "system cannot claim rules"}
			}
			now := s.now()
			r := store.Rule{Enabled: true, CreatedAt: now.UTC().Format(timeFormat), UpdatedAt: now.UTC().Format(timeFormat), CreatedBy: a.Who(), UpdatedBy: a.Who()}
			if e := applyPatch(&r, p, true, now); e != nil {
				return Result{}, e
			}
			c, e := Canonicalize(r.Match)
			if e != nil {
				return Result{}, e
			}
			canonicalRow(&r, c)
			key := r.GroupKey + r.CondKey
			old, ok := seen[key]
			readErr := error(nil)
			if !ok {
				old, readErr = store.Identity(s.db.Reader(), r.GroupKey, r.CondKey)
			}
			if readErr == nil {
				result, e := existingResult(old, r)
				if e == nil {
					seen[key] = result.Rule
				}
				return result, e
			}
			if !errors.Is(readErr, sql.ErrNoRows) {
				return Result{}, internal(readErr)
			}
			r.ID = "validate_" + strconv.Itoa(i)
			refs[r.ID] = "batch:" + strconv.Itoa(i)
			if e := s.admitWith(l, r, store.Rule{}); e != nil {
				return Result{}, e
			}
			if high >= 4294967295 {
				return Result{}, &Error{Code: "table_full", Table: "logical_id", Message: store.ErrLogicalFull.Error()}
			}
			high++
			r.LogicalID = high
			l.change(r, 1)
			seen[key] = r
			return Result{Rule: r}, nil
		}()
		if _, ok := refs[result.Rule.ID]; ok {
			result.Rule.ID = ""
		}
		if fail != nil {
			if id, ok := refs[fail.RuleID]; ok {
				fail.RuleID = id
			}
			for j, id := range fail.RuleIDs {
				if ref, ok := refs[id]; ok {
					fail.RuleIDs[j] = ref
				}
			}
		}
		results[i] = BatchResult{Index: i, Result: result, Error: fail}
	}
	return results
}
func (s *Service) Update(a Actor, id string, p RulePatch) (result store.Rule, e *Error) {
	e = s.withWrite(func(change *Change) *Error {
		r, err := store.Get(s.db, id)
		if err != nil {
			return missing(err)
		}
		old := r
		oldKey := r.GroupKey
		if e := applyPatch(&r, p, false, s.now()); e != nil {
			return e
		}
		c, e := Canonicalize(r.Match)
		if e != nil {
			return e
		}
		canonicalRow(&r, c)
		other, err := store.Identity(s.db, r.GroupKey, r.CondKey)
		if err == nil && other.ID != id {
			return conflict(other.ID)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return internal(err)
		}
		if e = s.admitWith(s.ledger, r, old); e != nil {
			return e
		}
		r.UpdatedAt = s.now().UTC().Format(timeFormat)
		r.UpdatedBy = a.Who()
		if err = s.transaction(func(tx *sql.Tx) error {
			return ruleChange(tx, a, "rule.update", r.ID, r.UpdatedAt, func() error { return store.UpdateRule(tx, r) })
		}); err != nil {
			if store.Unique(err) {
				if other, e := store.Identity(s.db, r.GroupKey, r.CondKey); e == nil {
					return conflict(other.ID)
				}
			}
			return internal(err)
		}
		s.ledger.change(old, -1)
		s.ledger.change(r, 1)
		change.RuleKeys = append(change.RuleKeys, oldKey, r.GroupKey)
		if oldKey != r.GroupKey {
			change.Moves = append(change.Moves, Move{id, oldKey, r.GroupKey})
		}
		result = r
		return nil
	})
	return
}
func (s *Service) SetEnabled(a Actor, id string, enabled bool) *Error {
	return s.withWrite(func(change *Change) *Error {
		r, err := store.Get(s.db, id)
		if err != nil {
			return missing(err)
		}
		old := r
		r.Enabled = enabled
		if enabled {
			c, e := Canonicalize(r.Match)
			if e != nil {
				return e
			}
			canonicalRow(&r, c)
			if e = s.admitWith(s.ledger, r, old); e != nil {
				return e
			}
		}
		r.UpdatedAt = s.now().UTC().Format(timeFormat)
		r.UpdatedBy = a.Who()
		if err = s.transaction(func(tx *sql.Tx) error {
			return ruleChange(tx, a, "rule.update", r.ID, r.UpdatedAt, func() error { return store.UpdateRule(tx, r) })
		}); err != nil {
			return internal(err)
		}
		s.ledger.change(old, -1)
		s.ledger.change(r, 1)
		change.RuleKeys = append(change.RuleKeys, r.GroupKey)
		return nil
	})
}
func (s *Service) ReleaseClaim(a Actor, id, ref string) *Error {
	return s.withWrite(func(c *Change) *Error {
		if a.Kind != Machine {
			return nil
		}
		r, err := store.Get(s.db, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return internal(err)
		}
		deleted := false
		err = s.transaction(func(tx *sql.Tx) error {
			before, err := ruleView(tx, id)
			if err != nil {
				return err
			}
			released, err := store.Release(tx, id, a.String(), ref)
			if err != nil || !released {
				return err
			}
			n, err := store.ClaimCount(tx, id)
			if err != nil {
				return err
			}
			if n == 0 {
				deleted = true
				if err := store.DeleteRule(tx, id); err != nil {
					return err
				}
			}
			return recordRule(tx, a, "rule.release", id, s.now().UTC().Format(timeFormat), before)
		})
		if err != nil {
			return internal(err)
		}
		if deleted {
			s.ledger.change(r, -1)
			c.RuleKeys = append(c.RuleKeys, r.GroupKey)
		}
		return nil
	})
}
func (s *Service) ForceDelete(a Actor, id string) *Error {
	return s.withWrite(func(c *Change) *Error {
		r, err := store.Get(s.db, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return internal(err)
		}
		if err = s.transaction(func(tx *sql.Tx) error {
			return ruleChange(tx, a, "rule.delete", id, s.now().UTC().Format(timeFormat), func() error { return store.DeleteRule(tx, id) })
		}); err != nil {
			return internal(err)
		}
		s.ledger.change(r, -1)
		c.RuleKeys = append(c.RuleKeys, r.GroupKey)
		return nil
	})
}
func (s *Service) ExpireDue(now time.Time) *Error {
	e := s.withWrite(func(c *Change) *Error {
		rows, err := store.Due(s.db, now.UTC().Format(timeFormat))
		if err != nil {
			return internal(err)
		}
		err = s.transaction(func(tx *sql.Tx) error {
			for _, r := range rows {
				r := r
				if err := ruleChange(tx, Actor{Kind: System, Name: "expiry"}, "rule.expire", r.ID, now.UTC().Format(timeFormat), func() error { return store.DeleteRule(tx, r.ID) }); err != nil {
					return err
				}
				c.RuleKeys = append(c.RuleKeys, r.GroupKey)
			}
			return nil
		})
		if err != nil {
			return internal(err)
		}
		for _, r := range rows {
			s.ledger.change(r, -1)
		}
		return nil
	})
	if e != nil {
		return e
	}
	return s.purgeAudit(now)
}
func (s *Service) Get(id string) (store.Rule, *Error) {
	r, e := store.Get(s.db.Reader(), id)
	if e != nil {
		return r, missing(e)
	}
	return r, nil
}
func (s *Service) List() ([]store.Rule, *Error) {
	rows, e := store.List(s.db.Reader())
	if e != nil {
		return nil, internal(e)
	}
	return rows, nil
}
func (s *Service) ListEnabledByGroup(key string) ([]store.Rule, *Error) {
	rows, e := store.EnabledByGroup(s.db.Reader(), key)
	if e != nil {
		return nil, internal(e)
	}
	return rows, nil
}
func (s *Service) CreateWhitelist(a Actor, in WhitelistInput) (result WLResult, e *Error) {
	e = s.withWrite(func(change *Change) *Error {
		c, e := CanonicalizeWhitelist(in)
		if e != nil {
			return e
		}
		find := func() (store.Whitelist, bool, error) {
			w, err := store.WhitelistIdentity(s.db, c.Key)
			if errors.Is(err, sql.ErrNoRows) {
				return w, false, nil
			}
			return w, err == nil, err
		}
		w, exists, err := find()
		if err != nil {
			return internal(err)
		}
		if exists {
			result = WLResult{w, true}
			return nil
		}
		if e := s.checkCapacityWith(s.ledger, Values{WhitelistDimension: 1}); e != nil {
			return e
		}
		id, err := newID("wl_")
		if err != nil {
			return internal(err)
		}
		w = store.Whitelist{ID: id, SrcIP: c.SrcIP, DstIP: c.DstIP, SrcPort: c.SrcPort, DstPort: c.DstPort, Protocol: c.Protocol, Key: c.Key, Comment: c.Comment, CreatedAt: s.now().UTC().Format(timeFormat), CreatedBy: a.Who()}
		err = s.transaction(func(tx *sql.Tx) error {
			if err := store.InsertWhitelist(tx, w); err != nil {
				return err
			}
			return record(tx, a, "whitelist.create", "whitelist:"+w.ID, nil, whitelistView(w), w.CreatedAt)
		})
		if store.Unique(err) {
			old, ok, e := find()
			if e == nil && ok {
				result = WLResult{old, true}
				return nil
			}
		}
		if err != nil {
			return internal(err)
		}
		s.ledger.occupancy.Used[WhitelistDimension]++
		result = WLResult{Whitelist: w}
		change.Whitelist = true
		return nil
	})
	return
}
func (s *Service) DeleteWhitelist(a Actor, id string) *Error {
	return s.withWrite(func(c *Change) *Error {
		err := s.transaction(func(tx *sql.Tx) error {
			w, err := store.GetWhitelist(tx, id)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			c.Whitelist, err = store.DeleteWhitelist(tx, id)
			if err != nil {
				return err
			}
			return record(tx, a, "whitelist.delete", "whitelist:"+id, whitelistView(w), nil, s.now().UTC().Format(timeFormat))
		})
		if err != nil {
			return internal(err)
		}
		if c.Whitelist {
			s.ledger.occupancy.Used[WhitelistDimension]--
		}
		return nil
	})
}
func (s *Service) ListWhitelist() ([]store.Whitelist, *Error) {
	rows, e := store.ListWhitelist(s.db.Reader())
	if e != nil {
		return nil, internal(e)
	}
	return rows, nil
}

func (s *Service) ListPage(after int64, limit int) ([]store.Rule, *Error) {
	rows, err := store.ListPage(s.db.Reader(), after, limit)
	if err != nil {
		return nil, internal(err)
	}
	return rows, nil
}

var queryRuleID = regexp.MustCompile(`^rule_[0-9a-f]{32}$`)

func (s *Service) QueryPage(raw, state string, counts bool, after int64, limit int) ([]store.Rule, map[string]int, *Error) {
	q := store.RuleQuery{Where: "1"}
	raw = strings.TrimSpace(raw)
	invalid := &Error{Code: "bad_request", Field: "q", Message: "invalid rule query"}
	switch {
	case raw == "":
	case queryRuleID.MatchString(raw):
		q.Where, q.Args = "id=?", []any{raw}
	default:
		prefix := strings.Contains(raw, "/")
		if addressFamily(raw, "", prefix) != nil {
			return nil, nil, invalid
		}
		if prefix {
			canonical, e := canonicalPrefix(raw)
			if e != nil {
				return nil, nil, invalid
			}
			q.Prefix, _ = netip.ParsePrefix(canonical)
		} else {
			ip, e := canonicalIP(raw)
			if e != nil || ip == "" {
				return nil, nil, invalid
			}
			addr := netip.MustParseAddr(ip)
			prefixes := []any{}
			for bits := 0; bits <= addr.BitLen(); bits++ {
				p, _ := canonicalPrefix(ip + "/" + strconv.Itoa(bits))
				prefixes = append(prefixes, p)
			}
			in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(prefixes)), ",") + ")"
			q.Where = "(src_ip=? OR dst_ip=? OR src_cidr IN " + in + " OR dst_cidr IN " + in + ")"
			q.Args = append(append([]any{ip, ip}, prefixes...), prefixes...)
		}
	}
	snapshot, err := s.db.BeginSnapshot()
	if err != nil {
		return nil, nil, internal(err)
	}
	defer snapshot.Close()
	rows, err := q.Page(snapshot.Tx, state, after, limit)
	var totals map[string]int
	if err == nil && counts {
		totals, err = q.Counts(snapshot.Tx)
	}
	if err != nil {
		return nil, nil, internal(err)
	}
	return rows, totals, nil
}
func (s *Service) ListWhitelistPage(after string, limit int) ([]store.Whitelist, *Error) {
	rows, err := store.ListWhitelistPage(s.db.Reader(), after, limit)
	if err != nil {
		return nil, internal(err)
	}
	return rows, nil
}
