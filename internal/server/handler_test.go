package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv9/fsa-mock/internal/config"
)

func post(t *testing.T, srv *httptest.Server, body string) map[string]any {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+"/jsonrpc", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("http status %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestEndToEnd_MaliciousAndClean(t *testing.T) {
	badBytes := []byte("EICAR-FAKE")
	sum := sha256.Sum256(badBytes)
	badHex := hex.EncodeToString(sum[:])

	cfg := &config.Config{
		DefaultMalwareName: "EICAR_TEST_FILE",
		DefaultScore:       90,
		DefaultCategory:    "Malware",
		BadHashes:          []config.BadHash{{Sha256: badHex}},
	}
	srv := httptest.NewServer(newHandler(cfg))
	defer srv.Close()

	login := post(t, srv, `{"method":"exec","params":[{"url":"/sys/login/user","user":"u","passwd":"p"}],"id":"1"}`)
	if login["session"] == nil || login["session"].(string) == "" {
		t.Fatalf("no session: %v", login)
	}

	check := func(name string, raw []byte, wantRating string) {
		b64 := base64.StdEncoding.EncodeToString(raw)
		fn := base64.StdEncoding.EncodeToString([]byte(name))
		submit := post(t, srv, `{"method":"set","params":[{"url":"/alert/ondemand/submit-file","file":"`+b64+`","filename":"`+fn+`"}],"id":"1"}`)
		sid := submit["result"].(map[string]any)["data"].(map[string]any)["sid"].(string)

		jobs := post(t, srv, `{"method":"get","params":[{"url":"/scan/result/get-jobs-of-submission","sid":"`+sid+`"}],"id":"1"}`)
		jids := jobs["result"].(map[string]any)["data"].(map[string]any)["jids"].([]any)
		if len(jids) != 1 {
			t.Fatalf("expected 1 jid, got %d", len(jids))
		}
		jid := jids[0].(string)

		scan := post(t, srv, `{"method":"get","params":[{"url":"/scan/result/job","jid":"`+jid+`"}],"id":"1"}`)
		data := scan["result"].(map[string]any)["data"].(map[string]any)
		if data["rating"] != wantRating {
			t.Fatalf("%s: rating = %v, want %s", name, data["rating"], wantRating)
		}
		s := sha256.Sum256(raw)
		if data["sha256"] != hex.EncodeToString(s[:]) {
			t.Fatalf("%s: sha256 mismatch", name)
		}
	}

	check("bad.bin", badBytes, "Malicious")
	check("clean.txt", []byte("hello world"), "Clean")
}

func TestAuthRejectsWrongCreds(t *testing.T) {
	cfg := &config.Config{User: "admin", Password: "secret"}
	srv := httptest.NewServer(newHandler(cfg))
	defer srv.Close()

	got := post(t, srv, `{"method":"exec","params":[{"url":"/sys/login/user","user":"x","passwd":"y"}],"id":"1"}`)
	if v, ok := got["session"]; ok && v != nil && v != "" {
		t.Fatalf("expected no session, got %v", got)
	}
}

func TestUnknownURLReturnsBusinessError(t *testing.T) {
	srv := httptest.NewServer(newHandler(&config.Config{}))
	defer srv.Close()

	resp, err := srv.Client().Post(srv.URL+"/jsonrpc", "application/json",
		bytes.NewBufferString(`{"method":"get","params":[{"url":"/nope"}],"id":"1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	code := m["result"].(map[string]any)["status"].(map[string]any)["code"].(float64)
	if code == 0 {
		t.Fatalf("expected non-zero status.code for unknown url")
	}
}
