package rules

import "github.com/littlewolf9527/xdrop/controller/core/condexpr"

const (
	TableLimit            = 500000
	TrieLimit             = 50000
	WhitelistLimit        = TrieLimit
	LogicalLimit          = 1000000
	DefaultLogicalReserve = 1000
	DimensionCount        = 10
	WhitelistDimension    = 4
	LogicalDimension      = 9
	TrieDimensionStart    = 5
	TrieDimensionCount    = 4
)

var trieBucketNames = [4]string{"sv4", "dv4", "sv6", "dv6"}

func DimensionNames() [DimensionCount]string {
	return [DimensionCount]string{"blacklist", "cidr_blacklist", "cond", "cidr_cond", "whitelist", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "logical_state"}
}

type Values [DimensionCount]int
type Overload struct {
	Dim         string
	Limit, Used int
}
type OverloadedNode struct {
	Name string
	Dims []Overload
}
type Limits struct {
	Values     Values
	Sources    [DimensionCount]string
	Overloaded []OverloadedNode
}
type Occupancy struct {
	Used                                      Values
	Total, FullKeys, NearKeys, LogicalReserve int
}

func BuiltinLimits() Limits {
	l := Limits{Values: Values{TableLimit, TableLimit, TableLimit, TableLimit, WhitelistLimit, TrieLimit, TrieLimit, TrieLimit, TrieLimit, LogicalLimit}, Overloaded: []OverloadedNode{}}
	for i := range l.Sources {
		l.Sources[i] = "builtin"
	}
	return l
}
func AdmissionLimit(dim, nodeLimit, reserve int) int {
	if dim == LogicalDimension {
		return nodeLimit - reserve
	}
	return nodeLimit
}
func (s *Service) UseLimits(f func() Limits) { s.mu.Lock(); defer s.mu.Unlock(); s.limits = f }
func (s *Service) UseLogicalReserve(n int)   { s.mu.Lock(); defer s.mu.Unlock(); s.reserve = n }
func (s *Service) currentLimits() Limits {
	if s.limits != nil {
		return s.limits()
	}
	l := BuiltinLimits()
	for i := TrieDimensionStart; i < TrieDimensionStart+TrieDimensionCount; i++ {
		l.Values[i] = s.trieLimit
	}
	return l
}
func (s *Service) Limits() Limits { s.mu.Lock(); defer s.mu.Unlock(); return s.currentLimits() }
func (s *Service) Occupancy() (Occupancy, *Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ensureLedger(); e != nil {
		return Occupancy{}, e
	}
	o := s.ledger.occupancy
	o.LogicalReserve = s.reserve
	return o, nil
}
func (s *Service) checkCapacityWith(l *ledger, delta Values) *Error {
	for i, used := range l.occupancy.Used {
		if delta[i] > 0 && used+delta[i] > AdmissionLimit(i, s.writeLimits.Values[i], s.reserve) {
			name := DimensionNames()[i]
			if i >= TrieDimensionStart && i < TrieDimensionStart+TrieDimensionCount {
				name = trieBucketNames[i-TrieDimensionStart]
			}
			return &Error{Code: "table_full", Table: name, Message: "capacity exceeded"}
		}
	}
	return nil
}
func candidateBand(n int) (full, near int) {
	if n == condexpr.MaxCandidates {
		full = 1
	}
	if n == condexpr.MaxCandidates-1 {
		near = 1
	}
	return
}
