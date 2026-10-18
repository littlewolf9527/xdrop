package main

import (
	"encoding/json"
	"fmt"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/eval"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type closeoutRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Auth   bool   `json:"auth"`
}

type closeoutGroup struct {
	prefix string
	auth   bool
}

// Resolve actual Group/Use expressions and lexical bindings, never receiver names.
func closeoutParseRoutes(source []byte) ([]closeoutRoute, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "routes.go", source, 0)
	if err != nil {
		return nil, err
	}
	type binding struct {
		group *closeoutGroup
		auth  bool
	}
	type scope struct {
		parent *scope
		values map[string]binding
	}
	var routes []closeoutRoute
	var walk func([]ast.Stmt, *scope) error
	var resolve func(ast.Expr, *scope) (binding, error)
	str := func(e ast.Expr) (string, error) {
		v, ok := e.(*ast.BasicLit)
		if !ok || v.Kind != token.STRING {
			return "", fmt.Errorf("route prefix must be a string literal")
		}
		return strconv.Unquote(v.Value)
	}
	resolve = func(e ast.Expr, env *scope) (binding, error) {
		if id, ok := e.(*ast.Ident); ok {
			for s := env; s != nil; s = s.parent {
				if b, exists := s.values[id.Name]; exists {
					return b, nil
				}
			}
			return binding{}, nil
		}
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return binding{}, nil
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return binding{}, nil
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if id.Name == "api" && sel.Sel.Name == "AuthMiddleware" {
				return binding{auth: true}, nil
			}
			if id.Name == "gin" && (sel.Sel.Name == "New" || sel.Sel.Name == "Default") {
				return binding{group: &closeoutGroup{}}, nil
			}
		}
		base, err := resolve(sel.X, env)
		if err != nil || base.group == nil || sel.Sel.Name != "Group" {
			return binding{}, err
		}
		if len(call.Args) == 0 {
			return binding{}, fmt.Errorf("Group lacks prefix")
		}
		prefix, err := str(call.Args[0])
		if err != nil {
			return binding{}, err
		}
		// Gin Group copies the parent's handlers at creation, before later Use calls.
		g := &closeoutGroup{prefix: base.group.prefix + prefix, auth: base.group.auth}
		for _, arg := range call.Args[1:] {
			b, err := resolve(arg, env)
			if err != nil {
				return binding{}, err
			}
			g.auth = g.auth || b.auth
		}
		return binding{group: g}, nil
	}
	walk = func(stmts []ast.Stmt, env *scope) error {
		local := &scope{parent: env, values: map[string]binding{}}
		for _, statement := range stmts {
			switch s := statement.(type) {
			case *ast.AssignStmt:
				for i, rhs := range s.Rhs {
					if i >= len(s.Lhs) {
						break
					}
					id, ok := s.Lhs[i].(*ast.Ident)
					if !ok {
						continue
					}
					v, err := resolve(rhs, local)
					if err != nil {
						return err
					}
					target := local
					if s.Tok == token.ASSIGN {
						// Assignment updates the nearest declaration; := stays local.
						for target != nil {
							if _, exists := target.values[id.Name]; exists {
								break
							}
							target = target.parent
						}
					}
					if target != nil {
						target.values[id.Name] = v
					}
				}
			case *ast.BlockStmt:
				if err := walk(s.List, local); err != nil {
					return err
				}
			case *ast.ExprStmt:
				call, ok := s.X.(*ast.CallExpr)
				if !ok {
					continue
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				b, err := resolve(sel.X, local)
				if err != nil {
					return err
				}
				if b.group == nil {
					continue
				}
				if sel.Sel.Name == "Use" {
					for _, arg := range call.Args {
						v, err := resolve(arg, local)
						if err != nil {
							return err
						}
						b.group.auth = b.group.auth || v.auth
					}
					continue
				}
				switch sel.Sel.Name {
				case "GET", "POST", "PUT", "DELETE":
					if len(call.Args) == 0 {
						return fmt.Errorf("route lacks path")
					}
					path, err := str(call.Args[0])
					if err != nil {
						return err
					}
					// Route registration also snapshots handlers; a later Use cannot protect it.
					routes = append(routes, closeoutRoute{sel.Sel.Name, b.group.prefix + path, b.group.auth})
				}
			}
		}
		return nil
	}
	found := false
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "main" {
			found = true
			if err := walk(fn.Body.List, nil); err != nil {
				return nil, err
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("main not found")
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Method+" "+routes[i].Path < routes[j].Method+" "+routes[j].Path })
	return routes, nil
}

func TestCloseoutRoutes(t *testing.T) {
	for _, c := range []struct {
		source string
		want   []closeoutRoute
	}{
		{`package main;func main(){root:=gin.New();guard:=api.AuthMiddleware("key");one:=root.Group("/a");one.Use(guard);two:=one.Group("/b");two.POST("/c",h)}`, []closeoutRoute{{"POST", "/a/b/c", true}}},
		{`package main;func main(){r:=gin.New();g:=r.Group("/public");{g:=r.Group("/private",api.AuthMiddleware("key"));g.GET("",h)};g.GET("",h)}`, []closeoutRoute{{"GET", "/private", true}, {"GET", "/public", false}}},
		{`package main;func main(){root:=gin.New();guard:=api.AuthMiddleware("key");one:=root.Group("/a");two:=one.Group("/b");one.Use(guard);two.POST("/c",h)}`, []closeoutRoute{{"POST", "/a/b/c", false}}},
		{`package main;func main(){root:=gin.New();guard:=api.AuthMiddleware("key");one:=root.Group("/a");one.POST("/c",h);one.Use(guard)}`, []closeoutRoute{{"POST", "/a/c", false}}},
		{`package main;func main(){router:=gin.New();authMiddleware:=api.AuthMiddleware("key");protected:=router.Group("/api/v1");protected.Use(authMiddleware);{protected=router.Group("/api/v1")};protected.GET("/rules",h)}`, []closeoutRoute{{"GET", "/api/v1/rules", false}}},
	} {
		got, err := closeoutParseRoutes([]byte(c.source))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Fatalf("AST control got=%v want=%v err=%v", got, c.want, err)
		}
	}
	mainPath := os.Getenv("XDROP_CLOSEOUT_MAIN")
	if mainPath == "" {
		mainPath = "main.go"
	}
	source, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := closeoutParseRoutes(source)
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("XDROP_CLOSEOUT_ROUTES")
	if path == "" {
		path = "sync/closeout/routes.json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want []closeoutRoute
	if err = json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Method+" "+want[i].Path < want[j].Method+" "+want[j].Path })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CLOSEOUT_WITNESS B-1 routes actual=%v expected=%v", got, want)
	}
	auth := 0
	seen := map[string]bool{}
	for _, r := range got {
		if r.Auth {
			auth++
		}
		k := r.Method + " " + r.Path
		if seen[k] {
			t.Fatalf("duplicate route %s", k)
		}
		seen[k] = true
	}
	if len(got) != 10 || auth != 8 {
		t.Fatalf("CLOSEOUT_WITNESS B-1 routes=%d auth=%d expected=10/8", len(got), auth)
	}
	if seen["GET /api/v1/rules/:id"] {
		t.Fatal("unexpected single-rule GET route")
	}
	if !seen["POST /api/v1/rules/commit"] {
		t.Fatal("commit positive control absent")
	}
	if strings.Contains(string(source), "CLOSEOUT_") {
		t.Fatal("production source contains closeout instrumentation")
	}
	if export := os.Getenv("XDROP_CLOSEOUT_ROUTE_EXPORT"); export != "" {
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(export, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("CLOSEOUT_ROUTES routes=%d auth=%d ast_controls=5", len(got), auth)
}

func closeoutOracleSet(t *testing.T, tables eval.Tables, rules []api.Rule) eval.B1RuleSet {
	t.Helper()
	rs := eval.B1RuleSet{}
	srcs, dsts := map[string]uint32{}, map[string]uint32{}
	counts := map[string]int{}
	identity := func(r api.Rule) string {
		return fmt.Sprintf("%s/%s/%s/%s/%d/%d/%s", r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR, r.SrcPort, r.DstPort, r.Protocol)
	}
	for _, r := range rules {
		counts[identity(r)]++
	}
	proto := map[string]uint8{"": 0, "all": 0, "tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}
	for _, r := range rules {
		v := eval.B1Rule{Rule: eval.Rule{ID: r.ID, Conditions: eval.Conditions{MinLength: r.PktLenMin, MaxLength: r.PktLenMax, Anomaly: r.MatchAnomaly}}, LogicalID: r.LogicalID, TTL: r.TTL, DSCP: r.DSCP, ICMPType: r.ICMPType, ICMPCode: r.ICMPCode, Fragment: r.Fragment, PktLen: r.PktLen}
		v.HasConditions = counts[identity(r)] > 1 || r.TTL != nil || r.DSCP != nil || r.ICMPType != nil || r.ICMPCode != nil || r.Fragment != nil || r.PktLen != nil || r.TcpFlags != "" || r.PktLenMin > 0 || (r.PktLenMax != 0 && r.PktLenMax != 65535) || r.MatchAnomaly != 0
		if r.Action == "rate_limit" {
			v.Rate = r.RateLimit
		}
		for _, word := range strings.Split(r.TcpFlags, ",") {
			word = strings.TrimSpace(word)
			negative := strings.HasPrefix(word, "!")
			word = strings.TrimPrefix(word, "!")
			for bit, name := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
				if word == name {
					v.FlagsMask |= 1 << bit
					if !negative {
						v.FlagsValue |= 1 << bit
					}
				}
			}
		}
		mask := eval.Mask(0)
		if r.SrcIP != "" || r.SrcCIDR != "" {
			mask |= eval.SrcIP
		}
		if r.DstIP != "" || r.DstCIDR != "" {
			mask |= eval.DstIP
		}
		if r.SrcPort != 0 {
			mask |= eval.SrcPort
		}
		if r.DstPort != 0 {
			mask |= eval.DstPort
		}
		if proto[r.Protocol] != 0 {
			mask |= eval.Protocol
		}
		combo := -1
		for _, n := range tables.Order {
			if tables.Masks[n] == mask {
				combo = n
				break
			}
		}
		if combo < 0 {
			t.Fatalf("oracle rule has no combo: %+v", r)
		}
		if r.SrcCIDR != "" || r.DstCIDR != "" {
			if r.SrcCIDR != "" {
				if srcs[r.SrcCIDR] == 0 {
					srcs[r.SrcCIDR] = uint32(len(srcs) + 1)
					rs.SrcPrefixes = append(rs.SrcPrefixes, eval.Prefix{Network: netip.MustParsePrefix(r.SrcCIDR), ID: srcs[r.SrcCIDR]})
				}
				v.CIDRKey.SrcID = srcs[r.SrcCIDR]
			}
			if r.DstCIDR != "" {
				if dsts[r.DstCIDR] == 0 {
					dsts[r.DstCIDR] = uint32(len(dsts) + 1)
					rs.DstPrefixes = append(rs.DstPrefixes, eval.Prefix{Network: netip.MustParsePrefix(r.DstCIDR), ID: dsts[r.DstCIDR]})
				}
				v.CIDRKey.DstID = dsts[r.DstCIDR]
			}
			v.CIDRKey.Sport, v.CIDRKey.Dport, v.CIDRKey.Proto = r.SrcPort, r.DstPort, proto[r.Protocol]
			rs.CIDR = append(rs.CIDR, v)
			rs.CIDRBitmap |= 1 << combo
		} else {
			if r.SrcIP != "" {
				v.Key.Src = netip.MustParseAddr(r.SrcIP)
			}
			if r.DstIP != "" {
				v.Key.Dst = netip.MustParseAddr(r.DstIP)
			}
			v.Key.Sport, v.Key.Dport, v.Key.Proto = r.SrcPort, r.DstPort, proto[r.Protocol]
			rs.Exact = append(rs.Exact, v)
			rs.ExactBitmap |= 1 << combo
		}
	}
	return rs
}

// Packet inputs specify both the serialized frame and independent semantic fields.
// Expected rules and whitelist come only from the Python model, never ELF state.
type closeoutOraclePacket struct {
	Name                                 string
	Src, Dst                             string
	Sport, Dport                         uint16
	Proto                                uint8
	Length                               uint16
	Flags, TTL, DSCP, Anomaly, FragClass uint8
	NonFirst, ICMPValid                  bool
	ICMPType, ICMPCode                   uint8
	Frame                                string
}

func (p closeoutOraclePacket) value() eval.B1Packet {
	return eval.B1Packet{Packet: eval.Packet{Tuple: eval.Tuple{Src: netip.MustParseAddr(p.Src), Dst: netip.MustParseAddr(p.Dst), Sport: p.Sport, Dport: p.Dport, Proto: p.Proto}, Length: p.Length, Flags: p.Flags, Anomaly: p.Anomaly}, TTL: p.TTL, DSCP: p.DSCP, FragClass: p.FragClass, NonFirst: p.NonFirst, ICMPValid: p.ICMPValid, ICMPType: p.ICMPType, ICMPCode: p.ICMPCode}
}
func TestCloseoutOracle(t *testing.T) {
	input := os.Getenv("XDROP_CLOSEOUT_ORACLE_INPUT")
	if input == "" {
		return
	} // Artifact mode, exercised explicitly by the generator.
	var cases map[string]struct {
		Rules, Whitelist []api.Rule
		Packets          []closeoutOraclePacket
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	tables, err := eval.LoadTables(root, eval.B1)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	out := map[string][]eval.B1Decision{}
	count := 0
	for _, name := range names {
		c := cases[name]
		set := closeoutOracleSet(t, tables, c.Rules)
		wl := closeoutOracleSet(t, tables, c.Whitelist)
		for _, r := range wl.Exact {
			set.Whitelist = append(set.Whitelist, r.Rule)
		}
		set.WhitelistBitmap = wl.ExactBitmap
		out[name] = []eval.B1Decision{}
		for _, p := range c.Packets {
			d, err := eval.EvaluateB1Cut54(tables, set, p.value())
			if err != nil {
				t.Fatalf("%s/%s oracle: %v", name, p.Name, err)
			}
			out[name] = append(out[name], d)
			count++
		}
	}
	raw, err = json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(os.Getenv("XDROP_CLOSEOUT_ORACLE_OUT"), append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("CLOSEOUT_ORACLE cases=%d packets=%d observations=0", len(cases), count)
}
