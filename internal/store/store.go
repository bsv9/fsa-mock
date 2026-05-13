package store

import "sync"

type FileHashes struct {
	Sha256   string
	Sha1     string
	Md5      string
	Filename string
}

// Store keeps in-memory mappings sid → file hashes and jid → sid, as required
// by the spec. It is safe for concurrent use.
type Store struct {
	mu       sync.RWMutex
	bySid    map[string]FileHashes
	jidToSid map[string]string
}

func New() *Store {
	return &Store{
		bySid:    make(map[string]FileHashes),
		jidToSid: make(map[string]string),
	}
}

func (s *Store) PutSubmission(sid string, h FileHashes) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bySid[sid] = h
}

func (s *Store) PutJob(jid, sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jidToSid[jid] = sid
}

func (s *Store) HashesByJid(jid string) (FileHashes, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sid, ok := s.jidToSid[jid]
	if !ok {
		return FileHashes{}, "", false
	}
	h, ok := s.bySid[sid]
	return h, sid, ok
}
