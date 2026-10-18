package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
)

func TestTD074CPUStatsAuthHost(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handlers{}
	protected := r.Group("/api/v1")
	protected.Use(AuthMiddleware("td074-test-only-key"))
	protected.GET("/stats/cpu", h.GetCPUStats)
	for _, key := range []string{"", "wrong-test-key"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/cpu", nil)
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("TD074_CPU invalid authentication accepted status=%d body=%s", w.Code, w.Body)
		}
	}
}

func TestTD074SnapshotOwnsCounts(t *testing.T) {
	online, possible := 4, 8
	h := &Handlers{}
	h.SetRateLimitSnapshot(ratelimit.Snapshot{Divisor: 4, Source: "auto", OnlineCPUs: &online, PossibleCPUs: &possible})
	online, possible = 77, 88
	if h.rateLimit.Divisor != 4 || h.rateLimit.Source != "auto" || *h.rateLimit.OnlineCPUs != 4 || *h.rateLimit.PossibleCPUs != 8 {
		t.Fatalf("TD074_SNAPSHOT aliased caller counts: %+v", h.rateLimit)
	}
}
