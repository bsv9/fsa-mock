package server

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bsv9/fsa-mock/internal/config"
	"github.com/bsv9/fsa-mock/internal/jsonrpc"
	"github.com/bsv9/fsa-mock/internal/store"
)

type handler struct {
	cfg   *config.Config
	store *store.Store
}

func newHandler(cfg *config.Config) *handler {
	return &handler{cfg: cfg, store: store.New()}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/jsonrpc" {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req jsonrpc.Request
	if err := json.Unmarshal(body, &req); err != nil || len(req.Params) == 0 {
		http.Error(w, "bad json-rpc envelope", http.StatusBadRequest)
		return
	}

	url := jsonrpc.ParamURL(req.Params[0])
	ip := clientIP(r)
	log.Printf("rpc %s from=%s session=%q bytes=%d", url, ip, redact(req.Session), len(body))

	switch url {
	case "/sys/login/user":
		h.login(w, &req, ip)
	case "/alert/ondemand/submit-file":
		h.submitFile(w, &req, ip)
	case "/scan/result/get-jobs-of-submission":
		h.jobsOfSubmission(w, &req, ip)
	case "/scan/result/job":
		h.scanResult(w, &req, ip)
	default:
		log.Printf("  -> unknown url %q", url)
		writeStatusError(w, &req, url, 1, "unknown url: "+url)
	}
}

// 1. Auth
func (h *handler) login(w http.ResponseWriter, req *jsonrpc.Request, ip string) {
	var p struct {
		User   string `json:"user"`
		Passwd string `json:"passwd"`
	}
	_ = json.Unmarshal(req.Params[0], &p)

	if h.cfg.User != "" || h.cfg.Password != "" {
		if p.User != h.cfg.User || p.Passwd != h.cfg.Password {
			log.Printf("  login DENIED user=%q from=%s", p.User, ip)
			// Spec: session==null means auth failed; HTTP must still be 2xx.
			writeJSON(w, jsonrpc.Response{ID: req.ID})
			return
		}
	}
	sess := randomHex(16)
	log.Printf("  login OK user=%q from=%s session=%q", p.User, ip, redact(sess))
	writeJSON(w, jsonrpc.Response{
		Session: sess,
		ID:      req.ID,
	})
}

// 2. Submit file
func (h *handler) submitFile(w http.ResponseWriter, req *jsonrpc.Request, ip string) {
	var p struct {
		File     string `json:"file"`
		Filename string `json:"filename"`
	}
	_ = json.Unmarshal(req.Params[0], &p)

	raw, err := base64.StdEncoding.DecodeString(p.File)
	if err != nil {
		log.Printf("  submit REJECT from=%s reason=base64", ip)
		writeStatusError(w, req, "/alert/ondemand/submit-file", 2, "file is not valid base64")
		return
	}
	name := ""
	if b, err := base64.StdEncoding.DecodeString(p.Filename); err == nil {
		name = string(b)
	}

	hashes := store.FileHashes{
		Sha256:   sumHex(sha256.New(), raw),
		Sha1:     sumHex(sha1.New(), raw),
		Md5:      sumHex(md5.New(), raw),
		Filename: name,
	}
	sid := randomHex(8)
	h.store.PutSubmission(sid, hashes)
	bad, match := h.matchBad(hashes)
	verdict := "Clean"
	if bad {
		verdict = "Malicious:" + pickStr(match.MalwareName, h.cfg.DefaultMalwareName)
	}
	log.Printf("  submit sid=%s file=%q size=%d sha256=%s sha1=%s md5=%s verdict=%s",
		sid, name, len(raw), hashes.Sha256, hashes.Sha1, hashes.Md5, verdict)

	writeJSON(w, jsonrpc.Response{
		ID: req.ID,
		Result: &jsonrpc.Result{
			URL:    "/alert/ondemand/submit-file",
			Status: jsonrpc.Status{Code: 0, Message: "OK"},
			Data: map[string]interface{}{
				"sid":   sid,
				"msg":   "submitted",
				"error": nil,
			},
		},
	})
}

// 3. Jobs of submission
func (h *handler) jobsOfSubmission(w http.ResponseWriter, req *jsonrpc.Request, ip string) {
	var p struct {
		Sid string `json:"sid"`
	}
	_ = json.Unmarshal(req.Params[0], &p)

	jid := p.Sid + "_0"
	delay := h.pickScanDelay()
	readyAt := time.Now().Add(delay)
	h.store.PutJob(jid, p.Sid, readyAt)
	log.Printf("  jobs sid=%s -> jid=%s scan_delay=%s ready_at=%s", p.Sid, jid, delay, readyAt.Format(time.RFC3339))

	writeJSON(w, jsonrpc.Response{
		ID: req.ID,
		Result: &jsonrpc.Result{
			URL:    "/scan/result/get-jobs-of-submission",
			Status: jsonrpc.Status{Code: 0, Message: "OK"},
			Data:   map[string]interface{}{"jids": []string{jid}},
		},
	})
}

// 4. Scan result
func (h *handler) scanResult(w http.ResponseWriter, req *jsonrpc.Request, ip string) {
	var p struct {
		Jid string `json:"jid"`
	}
	_ = json.Unmarshal(req.Params[0], &p)

	hashes, sid, readyAt, ok := h.store.JobInfo(p.Jid)
	if !ok {
		log.Printf("  result jid=%s UNKNOWN", p.Jid)
		writeStatusError(w, req, "/scan/result/job", 3, "unknown jid")
		return
	}

	nowT := time.Now()
	if nowT.Before(readyAt) {
		remaining := readyAt.Sub(nowT)
		log.Printf("  result jid=%s sid=%s PENDING remaining=%s", p.Jid, sid, remaining)
		writeJSON(w, jsonrpc.Response{
			ID: req.ID,
			Result: &jsonrpc.Result{
				URL:    "/scan/result/job",
				Status: jsonrpc.Status{Code: 0, Message: "OK"},
				Data: map[string]interface{}{
					"jid":           p.Jid,
					"sid":           sid,
					"scan_status":   0,
					"now":           nowT.Unix(),
					"error_message": nil,
				},
			},
		})
		return
	}

	bad, match := h.matchBad(hashes)
	now := nowT.Unix()

	data := map[string]interface{}{
		"jid":                     p.Jid,
		"start_ts":                now - 300,
		"finish_ts":               now - 10,
		"now":                     now,
		"untrusted":               0,
		"sha256":                  hashes.Sha256,
		"sha1":                    hashes.Sha1,
		"vid":                     1,
		"infected_os":             "WIN7x64SP1",
		"detection_os":            "WIN7x64SP1",
		"detail_url":              "https://fortisandbox.invalid/detail/" + p.Jid,
		"download_url":            "https://fortisandbox.invalid/download/" + p.Jid,
		"false_positive_negative": 0,
		"file_name":               hashes.Filename,
		"pwd_extn":                0,
		"sid":                     sid,
		"scan_status":             4,
		"error_message":           nil,
	}

	if bad {
		data["rating"] = "Malicious"
		data["score"] = pickInt(match.Score, h.cfg.DefaultScore)
		data["malware_name"] = pickStr(match.MalwareName, h.cfg.DefaultMalwareName)
		data["category"] = pickStr(match.Category, h.cfg.DefaultCategory)
		data["rating_source"] = "Sandbox"
	} else {
		data["rating"] = "Clean"
		data["score"] = 0
		data["malware_name"] = nil
		data["category"] = "Unknown"
		data["rating_source"] = "Sandbox"
	}
	log.Printf("  result jid=%s sid=%s file=%q rating=%s score=%v malware=%v category=%v",
		p.Jid, sid, hashes.Filename, data["rating"], data["score"], data["malware_name"], data["category"])

	writeJSON(w, jsonrpc.Response{
		ID: req.ID,
		Result: &jsonrpc.Result{
			URL:    "/scan/result/job",
			Status: jsonrpc.Status{Code: 0, Message: "OK"},
			Data:   data,
		},
	})
}

func (h *handler) matchBad(fh store.FileHashes) (bool, config.BadHash) {
	s256 := strings.ToLower(fh.Sha256)
	s1 := strings.ToLower(fh.Sha1)
	md := strings.ToLower(fh.Md5)
	for _, b := range h.cfg.BadHashes {
		if b.Sha256 != "" && strings.ToLower(b.Sha256) == s256 {
			return true, b
		}
		if b.Sha1 != "" && strings.ToLower(b.Sha1) == s1 {
			return true, b
		}
		if b.Md5 != "" && strings.ToLower(b.Md5) == md {
			return true, b
		}
	}
	return false, config.BadHash{}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeStatusError(w http.ResponseWriter, req *jsonrpc.Request, url string, code int, msg string) {
	// HTTP stays 2xx — business error encoded in result.status (per spec).
	writeJSON(w, jsonrpc.Response{
		ID: req.ID,
		Result: &jsonrpc.Result{
			URL:    url,
			Status: jsonrpc.Status{Code: code, Message: msg},
		},
	})
}

func sumHex(h hash.Hash, b []byte) string {
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	return r.RemoteAddr
}

func redact(s string) string {
	if len(s) <= 6 {
		return s
	}
	return s[:6] + "…"
}

func pickStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
// pickScanDelay returns a random delay drawn uniformly from
// [ScanDelayMinSec, ScanDelayMaxSec] seconds. Returns 0 when both are 0.
func (h *handler) pickScanDelay() time.Duration {
	lo, hi := h.cfg.ScanDelayMinSec, h.cfg.ScanDelayMaxSec
	if lo < 0 {
		lo = 0
	}
	if hi < lo {
		hi = lo
	}
	if hi == 0 {
		return 0
	}
	span := uint64(hi - lo + 1)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Duration(lo) * time.Second
	}
	n := binary.BigEndian.Uint64(b[:]) % span
	return time.Duration(uint64(lo)+n) * time.Second
}

func pickInt(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}
