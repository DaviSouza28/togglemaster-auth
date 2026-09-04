package main

import (
"encoding/json"
"net/http"
"net/http/httptest"
"strings"
"testing"
)

func TestHealthHandler(t *testing.T) {
app := &App{}

req := httptest.NewRequest(http.MethodGet, "/health", nil)
rec := httptest.NewRecorder()

app.healthHandler(rec, req)

if rec.Code != http.StatusOK {
t.Fatalf("expected status 200, got %d", rec.Code)
}

var body map[string]string
if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
t.Fatalf("failed to decode response: %v", err)
}

if body["status"] != "ok" {
t.Fatalf("expected status ok, got %q", body["status"])
}
}

func TestGenerateAPIKey(t *testing.T) {
key, err := generateAPIKey()
if err != nil {
t.Fatalf("unexpected error generating API key: %v", err)
}

if !strings.HasPrefix(key, "tm_key_") {
t.Fatalf("expected key prefix tm_key_, got %q", key)
}

if len(key) != 71 {
t.Fatalf("expected key length 71, got %d", len(key))
}
}

func TestGenerateAPIKeysAreDifferent(t *testing.T) {
first, err := generateAPIKey()
if err != nil {
t.Fatalf("unexpected error generating first key: %v", err)
}

second, err := generateAPIKey()
if err != nil {
t.Fatalf("unexpected error generating second key: %v", err)
}

if first == second {
t.Fatal("expected generated API keys to be different")
}
}

func TestHashAPIKeyIsDeterministic(t *testing.T) {
key := "tm_key_test"

first := hashAPIKey(key)
second := hashAPIKey(key)

if first != second {
t.Fatalf("expected deterministic hash, got %q and %q", first, second)
}

if len(first) != 64 {
t.Fatalf("expected SHA-256 hexadecimal hash length 64, got %d", len(first))
}
}

func TestValidateKeyRequiresBearerToken(t *testing.T) {
app := &App{}

req := httptest.NewRequest(http.MethodGet, "/validate", nil)
rec := httptest.NewRecorder()

app.validateKeyHandler(rec, req)

if rec.Code != http.StatusUnauthorized {
t.Fatalf("expected status 401, got %d", rec.Code)
}
}

func TestMasterKeyMiddlewareRejectsInvalidKey(t *testing.T) {
app := &App{
MasterKey: "correct-master-key",
}

nextCalled := false

next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
nextCalled = true
w.WriteHeader(http.StatusOK)
})

handler := app.masterKeyAuthMiddleware(next)

req := httptest.NewRequest(http.MethodPost, "/admin/keys", nil)
req.Header.Set("Authorization", "Bearer wrong-master-key")

rec := httptest.NewRecorder()

handler.ServeHTTP(rec, req)

if rec.Code != http.StatusForbidden {
t.Fatalf("expected status 403, got %d", rec.Code)
}

if nextCalled {
t.Fatal("next handler should not be called with invalid master key")
}
}

func TestMasterKeyMiddlewareAllowsValidKey(t *testing.T) {
app := &App{
MasterKey: "correct-master-key",
}

nextCalled := false

next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
nextCalled = true
w.WriteHeader(http.StatusOK)
})

handler := app.masterKeyAuthMiddleware(next)

req := httptest.NewRequest(http.MethodPost, "/admin/keys", nil)
req.Header.Set("Authorization", "Bearer correct-master-key")

rec := httptest.NewRecorder()

handler.ServeHTTP(rec, req)

if rec.Code != http.StatusOK {
t.Fatalf("expected status 200, got %d", rec.Code)
}

if !nextCalled {
t.Fatal("expected next handler to be called with valid master key")
}
}
