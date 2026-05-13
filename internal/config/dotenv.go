package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadDotEnv reads KEY=VALUE pairs from path and sets them in the process
// environment, but only for keys that are not already set. Missing files are
// not an error. Lines starting with '#' and blank lines are ignored. Values
// may be optionally wrapped in single or double quotes.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	lineno := 0
	for sc.Scan() {
		lineno++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimPrefix(line, "export ")
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return fmt.Errorf("%s:%d: invalid line", path, lineno)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if n := len(val); n >= 2 {
			first, last := val[0], val[n-1]
			if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
				val = val[1 : n-1]
			}
		}
		if _, ok := os.LookupEnv(key); ok {
			continue
		}
		if err := os.Setenv(key, val); err != nil {
			return err
		}
	}
	return sc.Err()
}
