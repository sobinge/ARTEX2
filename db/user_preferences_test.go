package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestUserPreferencesMergeAndRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	userKey := fmt.Sprintf("test-prefs-%d", time.Now().UnixNano())
	defer func() { _, _ = d.Exec(`DELETE FROM user_preferences WHERE user_key=$1`, userKey) }()
	ctx := context.Background()

	raw, _, found, err := d.GetUserPreferences(ctx, userKey)
	if err != nil || found || raw != nil {
		t.Fatalf("missing preference: raw=%q found=%v err=%v", raw, found, err)
	}

	if _, err := d.MergeUserPreferences(ctx, userKey, []byte(`{"findings":{"pageSize":100,"view":"flat"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.MergeUserPreferences(ctx, userKey, []byte(`{"findings":{"pageSize":50,"view":"flat"},"theme":"dark"}`)); err != nil {
		t.Fatal(err)
	}

	raw, updatedAt, found, err := d.GetUserPreferences(ctx, userKey)
	if err != nil {
		t.Fatal(err)
	}
	if !found || updatedAt.IsZero() {
		t.Fatalf("preference not found: raw=%q found=%v updated=%v", raw, found, updatedAt)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	var findings struct {
		PageSize float64 `json:"pageSize"`
		View     string  `json:"view"`
	}
	if err := json.Unmarshal(got["findings"], &findings); err != nil {
		t.Fatal(err)
	}
	if findings.PageSize != 50 || findings.View != "flat" || string(got["theme"]) != `"dark"` {
		t.Fatalf("unexpected merged preferences: %s", raw)
	}
}
