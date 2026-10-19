package api

import "testing"

func TestHCC16ConflictCodes(t *testing.T) {
	t.Run("node-duplicate", func(t *testing.T) {
		f := fresh(t)
		c5bAttach(t, f, nil)
		input := `{"name":"n2","base_url":"http://192.0.2.2","api_key":"TEST_ONLY_NODE_KEY"}`
		request(t, f.e, "POST", "/api/v1/nodes", "ui", input, 201)
		w := request(t, f.e, "POST", "/api/v1/nodes", "ui", input, 409)
		require(t, decoded[Error](t, w).Code == "rule_conflict", "duplicate node code")
	})
	t.Run("template-duplicate", func(t *testing.T) {
		f := c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
		input := `{"name":"dup","body":"x"}`
		f.call(t, "POST", "/templates", f.cookie, input, 201)
		w := f.call(t, "POST", "/templates", f.cookie, input, 409)
		require(t, decoded[Error](t, w).Code == "rule_conflict", "duplicate template code")
	})
}
