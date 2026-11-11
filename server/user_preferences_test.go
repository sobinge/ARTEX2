package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testSubjectToken(t *testing.T, key []byte, subject string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestUserPreferencesHandlers(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	key := []byte("user-preferences-test-signing-key")
	s := &Server{m: m, jwtKey: key}
	subject := fmt.Sprintf("test-prefs-%d", time.Now().UnixNano())
	defer func() { _, _ = m.pg.Exec(`DELETE FROM user_preferences WHERE user_key=$1`, subject) }()
	token := testSubjectToken(t, key, subject)

	request := func(method, body, tok string, handler http.HandlerFunc) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/me/preferences", strings.NewReader(body))
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}

	if w := request(http.MethodGet, "", "", s.getMyPreferences); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated read status=%d", w.Code)
	}

	patch := `{"preferences":{"findings":{"pageSize":100,"view":"flat"}}}`
	if w := request(http.MethodPatch, patch, token, s.patchMyPreferences); w.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", w.Code, w.Body.String())
	}

	w := request(http.MethodGet, "", token, s.getMyPreferences)
	if w.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Preferences struct {
			Findings struct {
				PageSize int    `json:"pageSize"`
				View     string `json:"view"`
			} `json:"findings"`
		} `json:"preferences"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Preferences.Findings.PageSize != 100 || got.Preferences.Findings.View != "flat" {
		t.Fatalf("preferences=%+v", got.Preferences)
	}

	// Another authenticated account must not see this row.
	otherToken := testSubjectToken(t, key, subject+"-other")
	other := request(http.MethodGet, "", otherToken, s.getMyPreferences)
	if other.Code != http.StatusOK || !strings.Contains(other.Body.String(), `"preferences":{}`) {
		t.Fatalf("other account read status=%d body=%s", other.Code, other.Body.String())
	}

	// Arrays and scalars are rejected as top-level preference documents.
	if w := request(http.MethodPatch, `{"preferences":[1,2]}`, token, s.patchMyPreferences); w.Code != http.StatusBadRequest {
		t.Fatalf("array patch status=%d want 400", w.Code)
	}
}
