// Phase 1 probe file — goebpf → cilium/ebpf migration.
//
// Purpose: keep `github.com/cilium/ebpf@v0.21.0` in go.mod after `go mod
// tidy` during the dual-library compile-check phase. Without any actual
// import of the package, tidy would prune it from the module graph and
// defeat the point of Phase 1 (proving the two libraries coexist in a
// single build without dependency-graph conflicts).
//
// A blank import here contributes nothing at runtime except the package's
// init() cost (cilium/ebpf's init is a no-op init registering type
// descriptors only). No runtime behavior change.
//
// Delete this file at the start of Phase 2 (loader cutover), when real
// imports of cilium/ebpf take over from goebpf. Tracked in
// docs/proposals/goebpf-to-cilium-migration.md §6 Phase 2, step 1.
package main

import _ "github.com/cilium/ebpf"
