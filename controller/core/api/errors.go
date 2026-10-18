package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

type Error struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Field   string   `json:"field,omitempty"`
	RuleID  string   `json:"rule_id,omitempty"`
	RuleIDs []string `json:"rule_ids,omitempty"`
	Table   string   `json:"table,omitempty"`
}

var errorStatus = map[string]int{
	"admin_required": 403, "last_admin": 409,
	"invalid_credentials": 401, "login_throttled": 429, "invalid_field": 400, "user_exists": 409, "user_not_found": 404, "last_user": 409, "credential_not_found": 404,
	"invalid_rule": 400, "empty_value": 400, "invalid_expires_in": 400, "mapped_ipv6": 400, "address_family_mismatch": 400,
	"bad_request": 400, "batch_too_large": 400, "unauthenticated": 401, "forbidden": 403,
	"not_found": 404, "node_not_found": 404, "route_not_found": 404, "method_not_allowed": 405,
	"rule_conflict": 409, "condition_capacity": 409, "cidr_overlap": 409, "table_full": 409, "gen_epoch_mismatch": 409, "internal": 500,
}

func (a *API) mapped(e *rules.Error) *Error {
	out := &Error{Code: e.Code, Message: e.Message, Field: e.Field, RuleID: e.RuleID, RuleIDs: e.RuleIDs, Table: e.Table}
	if _, ok := errorStatus[out.Code]; !ok {
		out.Code = "internal"
	}
	if out.Code == "internal" {
		a.log.Printf("internal: %s", e.Message)
		out = &Error{Code: "internal", Message: "internal error"}
	}
	return out
}
func (a *API) fail(c *gin.Context, e *Error) {
	status, ok := errorStatus[e.Code]
	if !ok || e.Code == "internal" {
		status = 500
		e = &Error{Code: "internal", Message: "internal error"}
	}
	c.AbortWithStatusJSON(status, e)
}
func (a *API) serviceError(c *gin.Context, e *rules.Error) bool {
	if e == nil {
		return false
	}
	a.fail(c, a.mapped(e))
	return true
}
func (a *API) recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				a.log.Printf("panic: %v\n%s", v, debug.Stack())
				if !c.Writer.Written() {
					a.fail(c, &Error{Code: "internal", Message: "internal error"})
				} else {
					c.Abort()
				}
			}
		}()
		c.Next()
	}
}
func (a *API) decode(c *gin.Context, target any, limit int64) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	err := d.Decode(target)
	if err == nil {
		var extra any
		if d.Decode(&extra) != io.EOF {
			err = errors.New("trailing data")
		}
	}
	if err == nil {
		return true
	}
	e := &Error{Code: "bad_request", Message: "invalid JSON request"}
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &typeError) {
		e.Field = typeError.Field
	}
	if strings.HasPrefix(err.Error(), "json: unknown field ") {
		e.Field = strings.TrimPrefix(err.Error(), "json: unknown field ")
		e.Field = strings.Trim(e.Field, "\"")
	}
	a.fail(c, e)
	return false
}
