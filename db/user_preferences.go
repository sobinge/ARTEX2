package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// GetUserPreferences returns the account's namespaced UI preferences and whether
// a row exists. Missing rows are not an error; callers should fall back to {}.
func (d *DB) GetUserPreferences(ctx context.Context, userKey string) (json.RawMessage, time.Time, bool, error) {
	var raw string
	var updatedAt time.Time
	err := d.QueryRowContext(ctx, `
SELECT preferences::text, updated_at
FROM user_preferences
WHERE user_key = $1`, userKey).Scan(&raw, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, err
	}
	return json.RawMessage(raw), updatedAt, true, nil
}

// MergeUserPreferences shallow-merges patch into the stored JSON object. Each UI
// area owns one top-level namespace (for example "findings"), so updating one
// page does not overwrite preferences owned by another page. The caller must
// pass a validated JSON object.
func (d *DB) MergeUserPreferences(ctx context.Context, userKey string, patch json.RawMessage) (time.Time, error) {
	var updatedAt time.Time
	err := d.QueryRowContext(ctx, `
INSERT INTO user_preferences(user_key, preferences)
VALUES ($1, $2::jsonb)
ON CONFLICT (user_key) DO UPDATE
SET preferences = user_preferences.preferences || EXCLUDED.preferences,
    updated_at = now()
RETURNING updated_at`, userKey, string(patch)).Scan(&updatedAt)
	return updatedAt, err
}
