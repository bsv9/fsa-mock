package store

import (
	"sync"
	"time"
)

type FileHashes struct {
	Sha256   string
	Sha1     string
	Md5      string
	Filename string
}

type jobInfo struct {
	sid     string
	readyAt time.Time
}

// Store keeps in-memory mappings sid → file hashes and jid → job info, as
// required by the spec. It is safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	bySid map[string]FileHashes
	byJid map[string]jobInfo
}

func New() *Store {
	return &Store{
		bySid: make(map[string]FileHashes),
		byJid: make(map[string]jobInfo),
	}
}

func (s *Store) PutSubmission(sid string, h FileHashes) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bySid[sid] = h
}

// PutJob registers a jid for a sid. readyAt is the wall-clock time at which
// the scan is considered complete; pass time.Now() to mark it ready immediately.
func (s *Store) PutJob(jid, sid string, readyAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byJid[jid] = jobInfo{sid: sid, readyAt: readyAt}
}

// JobInfo returns hashes, sid, and the scan ready time for jid.
func (s *Store) JobInfo(jid string) (FileHashes, string, time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ji, ok := s.byJid[jid]
	if !ok {
		return FileHashes{}, "", time.Time{}, false
	}
	h, ok := s.bySid[ji.sid]
	if !ok {
		return FileHashes{}, "", time.Time{}, false
	}
	return h, ji.sid, ji.readyAt, true
}
