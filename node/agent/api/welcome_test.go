package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

// Welcome needs no BPF maps. This records only the newly added welcome fixture.
func TestBingWelcomeGolden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/", (&Handlers{}).Welcome)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	actual := struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}{w.Code, w.Body.String()}
	const path = "../testdata/sync-jia/welcome_p11.json"
	if os.Getenv("P11_WRITE_GOLDEN") == "1" {
		b, err := json.MarshalIndent(map[string]interface{}{t.Name(): actual}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["sync_protocol"] != float64(11) || len(body) != 3 {
		t.Fatalf("P11 Welcome shape: %v", body)
	}
	expectedCases := map[string]struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}{}
	if err := json.Unmarshal(b, &expectedCases); err != nil {
		t.Fatal(err)
	}
	expected, exists := expectedCases[t.Name()]
	if actual.Status != 200 || !exists || actual != expected {
		t.Fatalf("true Welcome != welcome_p11.json: actual=%+v expected=%+v", actual, expected)
	}
}
