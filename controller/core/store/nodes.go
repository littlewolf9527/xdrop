package store

const schemaV5 = `
CREATE TABLE nodes (name TEXT PRIMARY KEY, base_url TEXT NOT NULL,
 key_nonce BLOB NOT NULL, key_cipher BLOB NOT NULL,
 created_at TEXT NOT NULL, created_by TEXT NOT NULL,
 updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);`

type Node struct {
	Name, BaseURL                              string
	KeyNonce, KeyCipher                        []byte
	CreatedAt, CreatedBy, UpdatedAt, UpdatedBy string
}

const nodeColumns = "name,base_url,key_nonce,key_cipher,created_at,created_by,updated_at,updated_by"

func scanNode(s interface{ Scan(...any) error }) (n Node, err error) {
	err = s.Scan(&n.Name, &n.BaseURL, &n.KeyNonce, &n.KeyCipher, &n.CreatedAt, &n.CreatedBy, &n.UpdatedAt, &n.UpdatedBy)
	return
}
func Nodes(q Queryer) ([]Node, error) {
	rows, err := q.Query("SELECT " + nodeColumns + " FROM nodes ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func FindNode(q Queryer, name string) (Node, error) {
	return scanNode(q.QueryRow("SELECT "+nodeColumns+" FROM nodes WHERE name=?", name))
}
func PutNode(q Queryer, n Node, create bool) error {
	if create {
		_, err := q.Exec("INSERT INTO nodes ("+nodeColumns+") VALUES(?,?,?,?,?,?,?,?)", n.Name, n.BaseURL, n.KeyNonce, n.KeyCipher, n.CreatedAt, n.CreatedBy, n.UpdatedAt, n.UpdatedBy)
		return err
	}
	_, err := q.Exec("UPDATE nodes SET base_url=?,key_nonce=?,key_cipher=?,updated_at=?,updated_by=? WHERE name=?", n.BaseURL, n.KeyNonce, n.KeyCipher, n.UpdatedAt, n.UpdatedBy, n.Name)
	return err
}
func DeleteNode(q Queryer, name string) error {
	_, err := q.Exec("DELETE FROM nodes WHERE name=?", name)
	return err
}
