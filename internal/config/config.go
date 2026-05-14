package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// BadHash describes a single sample that must produce a malicious verdict.
// Any combination of Sha256, Sha1, Md5 may be set; comparison is case-insensitive.
type BadHash struct {
	Sha256      string `json:"sha256,omitempty"`
	Sha1        string `json:"sha1,omitempty"`
	Md5         string `json:"md5,omitempty"`
	MalwareName string `json:"malware_name,omitempty"`
	Score       int    `json:"score,omitempty"`
	Category    string `json:"category,omitempty"`
}

type Config struct {
	// Listen address, e.g. ":8080". The service speaks plain HTTP; TLS
	// termination is expected to be handled by an upstream nginx proxy.
	Addr string

	// Optional credentials. When both are empty, any user/passwd pair is accepted.
	User     string
	Password string

	// Default malicious-verdict fields used when a BadHash entry does not override them.
	DefaultMalwareName string
	DefaultScore       int
	DefaultCategory    string

	// Simulated scan duration. When a job is created it becomes "ready" after
	// a random delay uniformly drawn from [ScanDelayMinSec, ScanDelayMaxSec].
	// Until then /scan/result/job returns scan_status=0 (pending). Defaults
	// to 5..30 seconds; set both to 0 to disable the delay.
	ScanDelayMinSec int
	ScanDelayMaxSec int

	BadHashes []BadHash
}

func Load() (*Config, error) {
	c := &Config{
		Addr:               envOr("FSA_ADDR", ":8080"),
		User:               os.Getenv("FSA_USER"),
		Password:           os.Getenv("FSA_PASSWORD"),
		DefaultMalwareName: envOr("FSA_MALWARE_NAME", "EICAR_TEST_FILE"),
		DefaultCategory:    envOr("FSA_CATEGORY", "Malware"),
	}
	c.DefaultScore = envInt("FSA_SCORE", 90)
	c.ScanDelayMinSec = envInt("FSA_SCAN_DELAY_MIN", 5)
	c.ScanDelayMaxSec = envInt("FSA_SCAN_DELAY_MAX", 30)
	if c.ScanDelayMaxSec < c.ScanDelayMinSec {
		return nil, fmt.Errorf("FSA_SCAN_DELAY_MAX (%d) < FSA_SCAN_DELAY_MIN (%d)", c.ScanDelayMaxSec, c.ScanDelayMinSec)
	}

	// Bad hashes can be supplied either as a JSON file (FSA_BAD_HASHES_FILE)
	// or as a comma-separated list of sha256/sha1/md5 hex strings (FSA_BAD_HASHES).
	if path := os.Getenv("FSA_BAD_HASHES_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read bad hashes file: %w", err)
		}
		if err := json.Unmarshal(raw, &c.BadHashes); err != nil {
			return nil, fmt.Errorf("parse bad hashes file: %w", err)
		}
	}
	if list := os.Getenv("FSA_BAD_HASHES"); list != "" {
		for _, h := range strings.Split(list, ",") {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			bh := BadHash{}
			switch len(h) {
			case 64:
				bh.Sha256 = h
			case 40:
				bh.Sha1 = h
			case 32:
				bh.Md5 = h
			default:
				return nil, fmt.Errorf("FSA_BAD_HASHES: %q is not a sha256/sha1/md5 hex string", h)
			}
			c.BadHashes = append(c.BadHashes, bh)
		}
	}
	return c, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
