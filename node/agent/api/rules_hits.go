package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

const hitsBatchSize, hitsLimit = 256, 10000

type RuleHit struct {
	RuleID     string `json:"rule_id"`
	LogicalID  uint32 `json:"logical_id"`
	MatchCount uint64 `json:"match_count"`
	DropCount  uint64 `json:"drop_count"`
	MatchBytes uint64 `json:"match_bytes"`
	DropBytes  uint64 `json:"drop_bytes"`
	LastHitNS  uint64 `json:"last_hit_ns"`
}

type HitsResponse struct {
	NowNS     uint64    `json:"now_ns"`
	Truncated bool      `json:"truncated"`
	Scanned   int       `json:"scanned"`
	Hits      []RuleHit `json:"hits"`
}

type hitCounter struct {
	LogicalID uint32
	HotNS     uint64
	LogicalRuleCounters
}

// Fixed-size pages are retained across scans; no rule-sized contiguous object
// or per-request snapshot copy is allocated. mu owns pages through encoding.
type hitsCache struct {
	mu         sync.Mutex
	pages      []*[hitsBatchSize]hitCounter
	latest     []uint64
	n, scanned int
	keys       [hitsBatchSize]uint32
	times      [hitsBatchSize]uint64
	bucket     hitsBucket
	values     []LogicalRuleCounters
	reply      []RuleHit
	encoded    []byte
	replyCut   bool
	started    time.Time
	nowNS      uint64
	reclaimSeq uint64
	truncated  bool
	err        error
	// Per-handler seams; nil selects the real map and clocks.
	lookup func(*ebpf.MapBatchCursor, []uint32, []uint64) (int, error)
	read   func(uint32, []LogicalRuleCounters) error
	clock  func() (uint64, error)
	wall   func() time.Time
}

func (s *hitsCache) at(i int) *hitCounter { return &s.pages[i/hitsBatchSize][i%hitsBatchSize] }
func (s *hitsCache) Len() int             { return s.n }
func (s *hitsCache) Swap(i, j int)        { a, b := s.at(i), s.at(j); *a, *b = *b, *a }
func (s *hitsCache) Less(i, j int) bool {
	a, b := s.at(i), s.at(j)
	if a.Drop != b.Drop {
		return a.Drop > b.Drop
	}
	return a.LogicalID < b.LogicalID
}

func (s *hitsCache) scan() error {
	s.n, s.scanned, s.truncated = 0, 0, false
	defer func() {
		log.Printf("hits_scan rows=%d dur_ms=%.3f truncated=%t", s.scanned, s.wall().Sub(s.started).Seconds()*1000, s.truncated)
	}()
	var cursor ebpf.MapBatchCursor
	for {
		n, err := s.lookup(&cursor, s.keys[:], s.times[:])
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			s.truncated = true
			return fmt.Errorf("scan hot IDs: %w", err)
		}
		s.scanned += n
		s.truncated = s.scanned >= 8192
		for i := 0; i < n; i++ {
			if e := s.read(s.keys[i], s.values); errors.Is(e, ebpf.ErrKeyNotExist) {
				continue
			} else if e != nil {
				return fmt.Errorf("read logical counter: %w", e)
			}
			if s.n == len(s.pages)*hitsBatchSize {
				s.pages = append(s.pages, new([hitsBatchSize]hitCounter))
				s.latest = append(s.latest, 0)
			}
			row := s.at(s.n)
			*row = hitCounter{LogicalID: s.keys[i], HotNS: s.times[i]}
			for _, cpu := range s.values {
				row.add(cpu)
			}
			s.n++
		}
		// An EOF can carry the final nonempty batch.
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
	}
}

func (h *Handlers) hitsJSON(since uint64) ([]byte, error) {
	s := &h.hits
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wall == nil {
		s.wall = time.Now
	}
	if s.clock == nil {
		s.clock = hitsClock
	}
	// The window starts at scan entry, including scanning and sorting time.
	if s.started.IsZero() || s.wall().Sub(s.started) >= 2*time.Second {
		h.rulesMu.RLock()
		s.reclaimSeq = h.logicalReclaimSeq
		h.rulesMu.RUnlock()
		s.started = s.wall()
		s.err = nil
		s.encoded = nil
		if s.lookup == nil || s.read == nil {
			s.err = errors.New("hot IDs or logical counters unavailable")
			return nil, s.err
		}
		if s.values == nil {
			cpus, err := ebpf.PossibleCPU()
			if err != nil {
				s.err = err
				return nil, err
			}
			s.values = make([]LogicalRuleCounters, cpus)
		}
		s.err = s.scan()
		if s.err == nil {
			s.nowNS, s.err = s.clock()
		}
		if s.err == nil {
			sort.Sort(s)
			clear(s.latest)
			for i := 0; i < s.n; i++ {
				s.latest[i/hitsBatchSize] = max(s.latest[i/hitsBatchSize], min(s.at(i).HotNS, s.at(i).LastHitNS))
			}
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.reply == nil {
		s.reply = make([]RuleHit, 0, hitsLimit)
	}
	r := HitsResponse{NowNS: s.nowNS, Scanned: s.scanned, Truncated: s.truncated, Hits: s.reply[:0]}
	changed := s.encoded == nil
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	for i := 0; i < s.n; i++ {
		if i%hitsBatchSize == 0 && s.latest[i/hitsBatchSize] < since {
			i += hitsBatchSize - 1
			continue
		}
		row := s.at(i)
		if row.HotNS < since || row.LastHitNS < since {
			continue
		}
		owner, ok := h.logicalOwners[row.LogicalID]
		if !ok || h.logicalReclaimedAt[row.LogicalID] > s.reclaimSeq {
			continue
		}
		if len(r.Hits) == hitsLimit {
			r.Truncated = true
			break
		}
		hit := RuleHit{owner, row.LogicalID, row.Match, row.Drop, row.MatchBytes, row.DropBytes, row.LastHitNS}
		if len(r.Hits) >= len(s.reply) || s.reply[len(r.Hits)] != hit {
			changed = true
		}
		r.Hits = append(r.Hits, hit)
	}
	changed = changed || len(r.Hits) != len(s.reply) || r.Truncated != s.replyCut
	s.reply, s.replyCut = r.Hits, r.Truncated
	if changed {
		// Published bytes remain immutable while concurrent HTTP writers use them.
		s.encoded, s.err = json.Marshal(r)
	}
	return s.encoded, s.err
}

// SetHits wires the unpinned candidate map before serving requests.
func (h *Handlers) SetHits(hot *ebpf.Map, rate int) {
	h.hits.bucket.rate = float64(rate)
	if hot != nil && h.idCounts != nil {
		h.hits.lookup = func(c *ebpf.MapBatchCursor, k []uint32, v []uint64) (int, error) {
			return hot.BatchLookup(c, k, v, nil)
		}
		h.hits.read = func(id uint32, v []LogicalRuleCounters) error { return h.idCounts.Lookup(id, v) }
	}
}

type hitsBucket struct {
	mu           sync.Mutex
	rate, tokens float64
	last         time.Time
	clock        func() time.Time
}

func (b *hitsBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.clock == nil {
		b.clock = time.Now
	}
	if b.rate == 0 {
		b.rate = 20
	}
	now := b.clock()
	if b.last.IsZero() {
		b.tokens = b.rate
	}
	b.tokens = min(b.rate, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (h *Handlers) Hits(c *gin.Context) {
	if !h.hits.bucket.allow() {
		c.Header("Retry-After", "1")
		c.Data(http.StatusTooManyRequests, "application/json; charset=utf-8", []byte("{\"error\":\"rate_limited\"}"))
		return
	}
	since, err := strconv.ParseUint(c.Query("since_ns"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "since_ns must be a uint64"})
		return
	}
	body, err := h.hitsJSON(since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}
