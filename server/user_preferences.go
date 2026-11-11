package server

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// maxUserPreferencesBytes bounds one account preference document. Preferences
// are small UI snapshots (view/filter/page sizes), not an arbitrary data store.
const maxUserPreferencesBytes = 64 << 10

// accountKey returns the authenticated JWT subject. requireAuth normally runs
// first, but handlers validate again so a direct call cannot bypass ownership.
func (s *Server) accountKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := jwtSubject(extractToken(r), s.jwtKey)
	if key == "" {
		writeErr(w, 401, "未授权")
		return "", false
	}
	return key, true
}

// GET /api/me/preferences — returns the current account's namespaced preferences.
func (s *Server) getMyPreferences(w http.ResponseWriter, r *http.Request) {
	key, ok := s.accountKey(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	raw, updatedAt, found, err := pg.GetUserPreferences(r.Context(), key)
	if err != nil {
		writeErr(w, 500, "读取偏好失败: "+err.Error())
		return
	}
	if !found || len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	updated := ""
	if !updatedAt.IsZero() {
		updated = updatedAt.UTC().Format(time.RFC3339Nano)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"preferences": raw,
		"updated_at":  updated,
	})
}

// PATCH /api/me/preferences — shallow-merges top-level namespaces into the
// account document. Pages must send their whole namespace value, not a patch of
// the namespace's fields, so a stale nested merge cannot erase sibling keys.
func (s *Server) patchMyPreferences(w http.ResponseWriter, r *http.Request) {
	key, ok := s.accountKey(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxUserPreferencesBytes))
	if err != nil {
		writeErr(w, 413, "偏好数据过大")
		return
	}
	var req struct {
		Preferences json.RawMessage `json:"preferences"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if !isJSONObject(req.Preferences) {
		writeErr(w, 400, "preferences 必须是 JSON 对象")
		return
	}
	updatedAt, err := pg.MergeUserPreferences(r.Context(), key, req.Preferences)
	if err != nil {
		writeErr(w, 500, "保存偏好失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":         true,
		"updated_at": updatedAt.UTC().Format(time.RFC3339Nano),
	})
}

func isJSONObject(raw []byte) bool {
	if len(raw) == 0 || !json.Valid(raw) {
		return false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return false
	}
	return object != nil
}
