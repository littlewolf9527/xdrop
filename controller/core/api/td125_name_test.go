package api

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"golang.org/x/crypto/bcrypt"
)

const td125NameMessage = "name must be 1..64 ASCII letters, digits, '.', '_' or '-', and not '.' or '..'"
const td125TestKey = "TEST_ONLY_td125_node_key"

func td125Accounts(t *testing.T) *c4aFixture {
	t.Helper()
	return c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
}

func td125SeedUsers(t *testing.T, f *c4aFixture) {
	t.Helper()
	u, err := store.FindUser(f.db.Reader(), "alice")
	require(t, err == nil, "read keeper")
	for _, name := range []string{"..", ".", "a b"} {
		u.ID, u.Username = 0, name
		require(t, store.InsertUser(f.db, u) == nil, "insert old user directly")
	}
}

func td125Nodes(t *testing.T) (*fixture, *NodeService) {
	t.Helper()
	f := fresh(t)
	s, _ := c5bAttach(t, f, nil)
	return f, s
}

func td125SeedNodes(t *testing.T, s *NodeService) {
	t.Helper()
	for _, name := range []string{"..", "a b", " lead"} {
		nonce, cipher, err := s.Key.Seal(name, td125TestKey)
		require(t, err == nil, "seal old node key")
		at := s.Now().UTC().Format(store.TimeFormat)
		row := store.Node{Name: name, BaseURL: "http://192.0.2.2", KeyNonce: nonce, KeyCipher: cipher, CreatedAt: at, UpdatedAt: at, CreatedBy: "system:test", UpdatedBy: "system:test"}
		require(t, store.PutNode(s.DB, row, true) == nil, "insert old node directly")
	}
}

func TestTD125G2HTTPCreate(t *testing.T) {
	t.Run("user-dotdot", func(t *testing.T) {
		f := td125Accounts(t)
		before := c4aCount(t, f.db, "SELECT COUNT(*) FROM audit")
		w := f.call(t, "POST", "/users", f.cookie, c4aJSON(UserInput{LoginInput{"..", "TEST_ONLY_td125_password"}, "admin"}), 400)
		e := decoded[Error](t, w)
		require(t, e.Code == "invalid_field" && e.Field == "username", "user error code/field")
		_, err := store.FindUser(f.db.Reader(), "..")
		require(t, err == sql.ErrNoRows && c4aCount(t, f.db, "SELECT COUNT(*) FROM audit") == before, "user rejected without writes")
	})
	t.Run("credential-dotdot", func(t *testing.T) {
		f := td125Accounts(t)
		before := c4aCount(t, f.db, "SELECT COUNT(*) FROM audit")
		w := f.call(t, "POST", "/credentials", f.cookie, c4aJSON(CredentialInput{".."}), 400)
		e := decoded[Error](t, w)
		require(t, e.Code == "invalid_field" && e.Field == "name", "credential error code/field")
		rows, err := store.Credentials(f.db.Reader())
		require(t, err == nil && len(rows) == 0 && c4aCount(t, f.db, "SELECT COUNT(*) FROM audit") == before, "credential rejected without writes")
	})
}

func TestTD125G3HTTPNodes(t *testing.T) {
	for _, tc := range []struct{ label, name string }{
		{"dot", "."}, {"dotdot", ".."}, {"space", "a b"}, {"leading-space", " a"},
		{"tab", "a\t"}, {"length-65", strings.Repeat("a", 65)}, {"non-ascii", "é"},
	} {
		t.Run("reject-"+tc.label, func(t *testing.T) {
			f, _ := td125Nodes(t)
			w := request(t, f.e, "POST", "/api/v1/nodes", "ui", c4aJSON(map[string]string{"name": tc.name, "base_url": "http://192.0.2.2", "api_key": td125TestKey}), 400)
			e := decoded[Error](t, w)
			require(t, e.Code == "invalid_field" && e.Message == td125NameMessage, "fixed name message", tc.label)
			_, err := store.FindNode(f.db.Reader(), tc.name)
			require(t, err == sql.ErrNoRows, "rejected node persisted", tc.label)
			require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM audit WHERE action='node.create'") == 0, "rejected create audit", tc.label)
		})
	}
	for _, tc := range []struct{ label, name string }{{"three-dots", "..."}, {"embedded-dots", "a..b"}, {"length-64", strings.Repeat("a", 64)}} {
		t.Run("accept-"+tc.label, func(t *testing.T) {
			f, _ := td125Nodes(t)
			request(t, f.e, "POST", "/api/v1/nodes", "ui", c4aJSON(map[string]string{"name": tc.name, "base_url": "http://192.0.2.2", "api_key": td125TestKey}), 201)
			_, err := store.FindNode(f.db.Reader(), tc.name)
			require(t, err == nil, "accepted node persisted", tc.label)
		})
	}
	for _, tc := range []struct{ label, name, message string }{
		{"slash", "region/node", "name must not contain '/'"}, {"empty", "", "name must not be empty"}, {"blank", " ", "name must not be empty"},
	} {
		t.Run("order-"+tc.label, func(t *testing.T) {
			f, _ := td125Nodes(t)
			w := request(t, f.e, "POST", "/api/v1/nodes", "ui", c4aJSON(map[string]string{"name": tc.name, "base_url": "http://192.0.2.2", "api_key": td125TestKey}), 400)
			e := decoded[Error](t, w)
			require(t, e.Code == "invalid_field" && e.Message == tc.message, "old message precedence", tc.label)
		})
	}
}

func TestTD125G3ServiceOldGuards(t *testing.T) {
	for _, operation := range []string{"update", "delete"} {
		for _, tc := range []struct{ label, name, message string }{
			{"slash", "region/node", "name must not contain '/'"}, {"empty", "", "name must not be empty"}, {"blank", " ", "name must not be empty"},
		} {
			t.Run(operation+"/"+tc.label, func(t *testing.T) {
				_, s := td125Nodes(t)
				patch := NodePatch{}
				if operation == "update" {
					url := "http://192.0.2.3"
					patch.BaseURL = &url
				}
				_, e := s.Change(rules.Actor{Kind: rules.System, Name: "test"}, operation, tc.name, patch)
				require(t, e != nil && e.Code == "invalid_field" && e.Message == tc.message, "old guards apply to every operation", tc.label)
			})
		}
	}
}

func TestTD125G4HTTPUsers(t *testing.T) {
	t.Run("list-all-old-names", func(t *testing.T) {
		f := td125Accounts(t)
		td125SeedUsers(t, f)
		rows := decoded[[]UserDTO](t, f.call(t, "GET", "/users", f.cookie, "", 200))
		seen := map[string]bool{}
		for _, row := range rows {
			seen[row.Username] = true
		}
		for _, name := range []string{"..", ".", "a b"} {
			require(t, seen[name], "old user omitted", name)
		}
	})
	t.Run("dotdot-password-raw-path", func(t *testing.T) {
		f := td125Accounts(t)
		td125SeedUsers(t, f)
		const next = "TEST_ONLY_td125_new_password"
		f.call(t, "PUT", "/users/../password", f.cookie, c4aJSON(PasswordInput{next}), 204)
		u, err := store.FindUser(f.db.Reader(), "..")
		require(t, err == nil && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(next)) == nil, "old user's new password stored")
	})
	t.Run("dotdot-role-raw-path", func(t *testing.T) {
		f := td125Accounts(t)
		td125SeedUsers(t, f)
		f.call(t, "PUT", "/users/../role", f.cookie, c4aJSON(RoleInput{"operator"}), 204)
		u, err := store.FindUser(f.db.Reader(), "..")
		require(t, err == nil && u.Role == "operator", "old user's new role stored")
	})
	for _, tc := range []struct{ label, name, path string }{
		{"dotdot-delete-raw-path", "..", "/users/.."}, {"dot-delete-raw-path", ".", "/users/."}, {"space-delete-encoded-path", "a b", "/users/a%20b"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			f := td125Accounts(t)
			td125SeedUsers(t, f)
			f.call(t, "DELETE", tc.path, f.cookie, "", 204)
			_, err := store.FindUser(f.db.Reader(), tc.name)
			require(t, err == sql.ErrNoRows, "old user gone")
		})
	}
}

func TestTD125G4HTTPCredentials(t *testing.T) {
	for _, operation := range []string{"list-dotdot", "revoke-dotdot-by-id"} {
		t.Run(operation, func(t *testing.T) {
			f := td125Accounts(t)
			const id = "test-only-td125-id"
			require(t, store.InsertCredential(f.db, store.Credential{ID: id, Name: "..", SecretHash: "TEST_ONLY_unused_hash", CreatedAt: f.now.Format(store.TimeFormat), CreatedBy: "system:test"}) == nil, "insert old credential directly")
			if operation == "list-dotdot" {
				rows := decoded[[]CredentialDTO](t, f.call(t, "GET", "/credentials", f.cookie, "", 200))
				require(t, len(rows) == 1 && rows[0].Name == ".." && rows[0].ID == id, "old credential listed")
			} else {
				f.call(t, "DELETE", "/credentials/"+id, f.cookie, "", 204)
				row, err := store.FindCredential(f.db.Reader(), id)
				require(t, err == nil && row.RevokedAt != nil && *row.RevokedAt != "", "old credential revoked")
			}
		})
	}
}

func TestTD125G4HTTPNodes(t *testing.T) {
	t.Run("list-all-old-names", func(t *testing.T) {
		f, s := td125Nodes(t)
		td125SeedNodes(t, s)
		rows := decoded[nodesResponse](t, request(t, f.e, "GET", "/api/v1/nodes", "ui", "", 200))
		seen := map[string]bool{}
		for _, row := range rows.Nodes {
			seen[row.Name] = true
		}
		for _, name := range []string{"..", "a b", " lead"} {
			require(t, seen[name], "old node omitted", name)
		}
	})
	t.Run("space-patch-url", func(t *testing.T) {
		f, s := td125Nodes(t)
		td125SeedNodes(t, s)
		request(t, f.e, "PATCH", "/api/v1/nodes/a%20b", "ui", `{"base_url":"http://192.0.2.3"}`, 200)
		row, err := store.FindNode(f.db.Reader(), "a b")
		require(t, err == nil && row.BaseURL == "http://192.0.2.3", "old node URL changed")
		plain, err := s.Key.Open("a b", row.KeyNonce, row.KeyCipher)
		require(t, err == nil && plain == td125TestKey, "URL-only update keeps key")
	})
	for _, tc := range []struct{ label, name, path string }{{"space-delete", "a b", "/api/v1/nodes/a%20b"}, {"dotdot-delete-raw-path", "..", "/api/v1/nodes/.."}} {
		t.Run(tc.label, func(t *testing.T) {
			f, s := td125Nodes(t)
			td125SeedNodes(t, s)
			request(t, f.e, "DELETE", tc.path, "ui", "", 204)
			_, err := store.FindNode(f.db.Reader(), tc.name)
			require(t, err == sql.ErrNoRows, "old node gone")
		})
	}
}

func TestTD125G4ServiceOldNodeKey(t *testing.T) {
	t.Run("space-update-key-only", func(t *testing.T) {
		f, s := td125Nodes(t)
		td125SeedNodes(t, s)
		next := "TEST_ONLY_td125_new_node_key"
		_, e := s.Change(rules.Actor{Kind: rules.System, Name: "test"}, "update", "a b", NodePatch{APIKey: &next})
		require(t, e == nil, "old node key-only update")
		row, err := store.FindNode(f.db.Reader(), "a b")
		require(t, err == nil && row.BaseURL == "http://192.0.2.2", "key-only update keeps URL")
		plain, err := s.Key.Open("a b", row.KeyNonce, row.KeyCipher)
		require(t, err == nil && plain == next, "new node key decrypts exactly")
	})
}
