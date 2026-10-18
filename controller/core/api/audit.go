package api

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type AuditDTO struct {
	ID     int64           `json:"id"`
	At     string          `json:"at"`
	Actor  string          `json:"actor"`
	Source string          `json:"source"`
	Action string          `json:"action"`
	Target string          `json:"target"`
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
}

func auditDTO(e store.AuditEvent) AuditDTO {
	return AuditDTO{e.ID, e.At, e.Actor, e.Source, e.Action, e.Target, e.Before, e.After}
}

type auditCursor struct {
	At string
	ID int64
}

func auditTime(v string) bool {
	t, err := time.Parse(store.TimeFormat, v)
	return err == nil && t.Format(store.TimeFormat) == v
}
func (a *API) auditInvalid(c *gin.Context, field string) {
	a.fail(c, &Error{Code: "invalid_field", Message: "invalid field", Field: field})
}
func (a *API) auditRange(c *gin.Context, required bool) (string, string, bool) {
	for _, field := range []string{"from", "to"} {
		v := c.Query(field)
		if (required || v != "") && !auditTime(v) {
			a.auditInvalid(c, field)
			return "", "", false
		}
	}
	return c.Query("from"), c.Query("to"), true
}
func (a *API) auditPage(c *gin.Context) {
	from, to, ok := a.auditRange(c, false)
	if !ok {
		return
	}
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if err != nil || limit < 1 || limit > 1000 {
		a.auditInvalid(c, "limit")
		return
	}
	var cursor auditCursor
	if v := c.Query("cursor"); v != "" {
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil || json.Unmarshal(b, &cursor) != nil || !auditTime(cursor.At) || cursor.ID < 1 {
			a.auditInvalid(c, "cursor")
			return
		}
	}
	rows, e := a.service.AuditPageAction(c.Query("action"), from, to, cursor.At, cursor.ID, limit+1)
	if a.serviceError(c, e) {
		return
	}
	out := struct {
		Items      []AuditDTO `json:"items"`
		NextCursor string     `json:"next_cursor"`
	}{Items: []AuditDTO{}}
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[limit-1]
		b, _ := json.Marshal(auditCursor{last.At, last.ID})
		out.NextCursor = base64.RawURLEncoding.EncodeToString(b)
	}
	for _, e := range rows {
		out.Items = append(out.Items, auditDTO(e))
	}
	c.JSON(200, out)
}
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
func (a *API) auditExport(c *gin.Context) {
	from, to, ok := a.auditRange(c, true)
	if !ok {
		return
	}
	format := c.Query("format")
	action := c.Query("action")
	if format != "csv" && format != "json" {
		a.auditInvalid(c, "format")
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="xdrop-audit-%s-%s.%s"`, from, to, format))
	types := map[string]string{"csv": "text/csv; charset=utf-8", "json": "application/json"}
	c.Header("Content-Type", types[format])
	abort := func(err error) {
		if err != nil {
			a.log.Print("audit export interrupted")
			panic(http.ErrAbortHandler)
		}
	}
	write := func(v string) error { _, err := io.WriteString(c.Writer, v); return err }
	if format == "json" {
		abort(write("["))
		first := true
		encoder := json.NewEncoder(c.Writer)
		abort(a.service.AuditExportAction(action, from, to, func(e store.AuditEvent) error {
			if !first {
				if err := write(","); err != nil {
					return err
				}
			}
			first = false
			return encoder.Encode(auditDTO(e))
		}))
		abort(write("]"))
		return
	}
	w := csv.NewWriter(c.Writer)
	abort(w.Write([]string{"id", "at", "actor", "source", "action", "target", "before", "after"}))
	abort(a.service.AuditExportAction(action, from, to, func(e store.AuditEvent) error {
		row := []string{strconv.FormatInt(e.ID, 10), e.At, e.Actor, e.Source, e.Action, e.Target, string(e.Before), string(e.After)}
		for i := range row {
			row[i] = csvCell(row[i])
		}
		return w.Write(row)
	}))
	w.Flush()
	abort(w.Error())
}
