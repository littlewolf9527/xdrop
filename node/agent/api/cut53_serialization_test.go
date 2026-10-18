package api

import (
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCut53RuleValueProducers(t *testing.T) {
	// Bind the universal serialization property below to the complete production
	// producer census. Empty error-return values and test fixtures are excluded.
	want := map[string]int{"condition_atomic.go:prepareAtomicRule": 2}

	got := map[string]int{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || len(lit.Elts) == 0 {
					return true
				}
				name, ok := lit.Type.(*ast.Ident)
				if ok && name.Name == "RuleValue" {
					got[path+":"+fn.Name.Name]++
					hasLogicalID := false
					for _, element := range lit.Elts {
						if field, ok := element.(*ast.KeyValueExpr); ok {
							if key, ok := field.Key.(*ast.Ident); ok && key.Name == "LogicalID" {
								hasLogicalID = true
							}
						}
					}
					if !hasLogicalID {
						t.Fatalf("production RuleValue producer omitted logical ID: %s:%s", path, fn.Name.Name)
					}

				}
				return true
			})
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("W11 producer census=%v want=%v", got, want)
	}
	for producer, count := range got {
		for ordinal := 0; ordinal < count; ordinal++ {
			t.Run(producer, func(t *testing.T) {
				for bits := 0; bits < 256; bits++ {
					v := RuleValue{Action: ActionRateLimit, RateLimit: 123, TcpFlagsMask: uint8(bits), TcpFlagsValue: uint8(255 - bits), MatchAnomaly: uint8(bits), PktLenMin: uint16(bits + 1), PktLenMax: uint16(65535 - bits), LogicalID: 7, LogicalReserved: [12]byte{9}, Pad2: [4]byte{RuleHasConditions, 255, 255, 255}}
					wire := ruleValueToBytes(v)
					if wire[1] != 0 || wire[2] != 0 || wire[3] != 0 || binary.LittleEndian.Uint32(wire[24:28]) != 0 || !reflect.DeepEqual(wire[28:32], []byte{1, 0, 0, 0}) {
						t.Fatalf("W11 producer=%s old fields survived: %x", producer, wire)
					}
					if wire[0] != ActionRateLimit || binary.LittleEndian.Uint32(wire[4:8]) != 123 || binary.LittleEndian.Uint32(wire[8:12]) != 7 || !reflect.DeepEqual(wire[12:24], make([]byte, 12)) {
						t.Fatal("W11 zeroing changed unrelated fields")
					}
				}
			})
		}
	}
	t.Log("CUT53_W11 production_constructors=2 serialization_cells=512 flag1_old_predicates=0")
}
