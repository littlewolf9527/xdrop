package api

import ()

// Key/value fake supports actual trie enumeration for both copies.
type fakeTrie = cut55Trie

func newFakeTrie() *fakeTrie { return &fakeTrie{rows: map[string]uint32{}} }
