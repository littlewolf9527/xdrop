package rules

import (
	"reflect"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

// RulePatch is also the create DTO: nil means omitted, a pointer means supplied.
// Empty strings clear fields on update and are rejected on creation.
type RulePatch struct {
	SrcIP        *string `json:"src_ip"`
	DstIP        *string `json:"dst_ip"`
	SrcCIDR      *string `json:"src_cidr"`
	DstCIDR      *string `json:"dst_cidr"`
	SrcPort      *int    `json:"src_port"`
	DstPort      *int    `json:"dst_port"`
	Protocol     *string `json:"protocol"`
	TTL          *string `json:"ttl"`
	DSCP         *string `json:"dscp"`
	ICMPType     *string `json:"icmp_type"`
	ICMPCode     *string `json:"icmp_code"`
	Fragment     *string `json:"fragment"`
	PktLen       *string `json:"pkt_len"`
	TCPFlags     *string `json:"tcp_flags"`
	MatchAnomaly *int    `json:"match_anomaly"`
	Action       *string `json:"action"`
	RateLimit    *int64  `json:"rate_limit"`
	Enabled      *bool   `json:"enabled"`
	Comment      *string `json:"comment"`
	ExpiresIn    *string `json:"expires_in"`
}

const timeFormat = store.TimeFormat

func applyPatch(r *store.Rule, p RulePatch, create bool, now time.Time) *Error {
	values := reflect.ValueOf(p)
	dest := reflect.ValueOf(r).Elem()
	for i := 0; i < values.NumField(); i++ {
		v, field := values.Field(i), values.Type().Field(i)
		if v.IsNil() {
			continue
		}
		if create && field.Name != "Comment" && v.Elem().Kind() == reflect.String && v.Elem().String() == "" {
			return &Error{Code: "empty_value", Field: field.Tag.Get("json"), Message: "explicit empty value is not permitted on create"}
		}
		if field.Name == "ExpiresIn" {
			continue
		}
		d := dest.FieldByName(field.Name)
		if d.Kind() == reflect.Pointer {
			if v.Elem().String() == "" {
				d.Set(reflect.Zero(d.Type()))
			} else {
				copy := reflect.New(d.Type().Elem())
				copy.Elem().Set(v.Elem())
				d.Set(copy)
			}
		} else {
			d.Set(v.Elem())
		}
	}
	if p.ExpiresIn != nil {
		r.ExpiresAt = nil
		if *p.ExpiresIn != "" {
			d, err := time.ParseDuration(*p.ExpiresIn)
			if err != nil || d <= 0 {
				return &Error{Code: "invalid_expires_in", Message: "expires_in must be a positive duration"}
			}
			stamp := now.Add(d).UTC().Format(timeFormat)
			r.ExpiresAt = &stamp
		}
	}
	return nil
}
