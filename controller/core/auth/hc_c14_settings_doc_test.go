package auth

import (
	"fmt"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestHCC14Settings(t *testing.T) {
	s, _, _ := c4aService(t)
	var p SettingsPatch
	fields := []struct {
		name                string
		max, upper, initial int
		target              **int
	}{
		{"session_hours", maxSessionHours, 720, 24, &p.SessionHours},
		{"audit_retention_days", maxAuditRetentionDays, 3650, 180, &p.AuditRetentionDays},
		{"history_retention_days", maxHistoryRetentionDays, 90, 30, &p.HistoryRetentionDays},
		{"reconcile_interval_minutes", maxReconcileIntervalMinutes, 1440, 15, &p.ReconcileIntervalMinutes},
	}
	actor := rules.Actor{Kind: rules.System, Name: "test"}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			for _, n := range []int{f.upper, f.upper + 1, 0} {
				t.Run(strconv.Itoa(n), func(t *testing.T) {
					*f.target = &n
					e := s.UpdateSettings(actor, p)
					*f.target = nil
					c4aCheck(t, (e == nil) == (n == f.upper), fmt.Sprintf("%s=%d: %+v", f.name, n, e))
					c4aCheck(t, e == nil || (e.Code == "invalid_field" && e.Field == f.name), fmt.Sprintf("rejection: %+v", e))
				})
			}
		})
	}
	languages := []string{"en-US", "zh-CN", "ja-JP"}
	codes := map[int]bool{}
	for i, lang := range append(append([]string{}, languages...), "", "unknown-language") {
		t.Run("default_language/"+lang, func(t *testing.T) {
			code := store.LanguageCode(lang)
			valid := i < len(languages)
			e := s.UpdateSettings(actor, SettingsPatch{DefaultLanguage: &lang})
			c4aCheck(t, (e == nil) == valid, fmt.Sprintf("language %q: %+v", lang, e))
			if valid {
				codes[code] = true
			} else {
				c4aCheck(t, e.Code == "invalid_field" && e.Field == "default_language", fmt.Sprintf("rejection: %+v", e))
				t.Logf("UpdateSettings: %+v", e)
			}
		})
	}
	c4aCheck(t, len(codes) == maxDefaultLanguage && !codes[0], fmt.Sprintf("language codes=%v max=%d", codes, maxDefaultLanguage))
	for _, file := range []string{"../../API.md", "../../API.zh.md", "../API.md", "../API.zh.md"} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(file)
			c4aCheck(t, err == nil, fmt.Sprintf("%s: %v", file, err))
			doc := string(raw)
			for _, f := range fields {
				pattern := `(?m)^\| ` + f.name + ` \| [0-9]+ \| 1(?:\.\.|…)([0-9]+) \|`
				if strings.HasPrefix(file, "../API") {
					pattern = fmt.Sprintf(`1(?:\.\.|…)([0-9]+)/%d\b`, f.initial)
				}
				m := regexp.MustCompile(pattern).FindAllStringSubmatch(doc, -1)
				c4aCheck(t, len(m) == 1, fmt.Sprintf("%s %s: range matches=%d", file, f.name, len(m)))
				got, _ := strconv.Atoi(m[0][1])
				c4aCheck(t, got == f.max, fmt.Sprintf("%s %s: doc=%d constant=%d", file, f.name, got, f.max))
			}
			if strings.HasPrefix(file, "../API") {
				m := regexp.MustCompile(`history_retention_days.*(?:range |范围 )1(?:\.\.|…)([0-9]+)`).FindAllStringSubmatch(doc, -1)
				c4aCheck(t, len(m) == 1, file+" history_retention_days independent range")
				n, _ := strconv.Atoi(m[0][1])
				c4aCheck(t, n == maxHistoryRetentionDays, file+" history_retention_days")
			}
			seen := map[string]bool{}
			line := regexp.MustCompile(`(?m)^(?:\| default_language \|.*|GET /settings .*)$`).FindString(doc)
			for _, lang := range regexp.MustCompile(`[a-z]{2}-[A-Z]{2}`).FindAllString(line, -1) {
				seen[lang] = true
			}
			c4aCheck(t, len(seen) == len(languages), file+" default_language count")
			for _, lang := range languages {
				c4aCheck(t, seen[lang], file+" default_language missing "+lang)
			}
		})
	}
}
