package api

import (
	"encoding/json"
	"errors"

	"github.com/gin-gonic/gin"
)

func bindStrictJSON(c *gin.Context, v any) error {
	if c.Request == nil || c.Request.Body == nil {
		return errors.New("invalid request")
	}
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	return d.Decode(v)
}
