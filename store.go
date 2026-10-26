package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// ProofRecord is a proof the node verified and emitted on its event stream.
type ProofRecord struct {
	Key            string    `json:"key"`
	Received       time.Time `json:"received"`
	BlockRoot      string    `json:"block_root"`
	Slot           uint64    `json:"slot,omitempty"`
	ProofType      uint8     `json:"proof_type"`
	ProofTypeName  string    `json:"proof_type_name"`
	ValidatorIndex uint64    `json:"validator_index"`
	Size           int       `json:"size"`
	ViaGateway     bool      `json:"via_gateway"`
	// SeenBy lists the nodes whose event stream delivered the proof.
	SeenBy []string `json:"seen_by"`
}

// SubmittedProof is one envelope of a submission and the node's verdict on it.
type SubmittedProof struct {
	Key            string `json:"key"`
	BlockRoot      string `json:"block_root"`
	ProofType      uint8  `json:"proof_type"`
	ProofTypeName  string `json:"proof_type_name"`
	ValidatorIndex uint64 `json:"validator_index"`
	Size           int    `json:"size"`
	// Accepted is set when at least one node accepted the proof.
	Accepted bool `json:"accepted"`
	// Errors holds the rejection of each node that rejected the proof.
	Errors map[string]string `json:"errors,omitempty"`
}

// Submission is one POST through the gateway.
type Submission struct {
	Time   time.Time        `json:"time"`
	Format string           `json:"format"`
	Status int              `json:"status"`
	Error  string           `json:"error,omitempty"`
	Proofs []SubmittedProof `json:"proofs"`
	// Nodes holds the HTTP status (0: unreachable) each node answered with.
	Nodes map[string]int `json:"nodes"`
}

type state struct {
	Proofs      []*ProofRecord `json:"proofs"`
	Submissions []*Submission  `json:"submissions"`
}

// Store keeps the most recent proofs (their envelopes on disk) and submissions.
type Store struct {
	dir  string
	keep int

	mu          sync.RWMutex
	proofs      []*ProofRecord // newest first
	byKey       map[string]*ProofRecord
	submissions []*Submission // newest first
	// submitted holds the keys of proofs submitted through the gateway, which
	// may arrive on the event stream before the submission completes.
	submitted map[string]time.Time
}

func NewStore(dir string, keep int) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "proofs"), 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:       dir,
		keep:      keep,
		byKey:     map[string]*ProofRecord{},
		submitted: map[string]time.Time{},
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err == nil {
		var st state
		if err := json.Unmarshal(data, &st); err != nil {
			slog.Warn("ignoring unreadable state", "err", err)
		} else {
			s.proofs = st.Proofs
			s.submissions = st.Submissions
			for _, p := range s.proofs {
				s.byKey[p.Key] = p
			}
		}
	}
	return s, nil
}

func (s *Store) proofPath(key string) string {
	return filepath.Join(s.dir, "proofs", key+".json")
}

// MarkSubmitted records proof keys as submitted through the gateway.
func (s *Store) MarkSubmitted(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, key := range keys {
		s.submitted[key] = now
		if p := s.byKey[key]; p != nil {
			p.ViaGateway = true
		}
	}
	for key, at := range s.submitted {
		if now.Sub(at) > time.Hour {
			delete(s.submitted, key)
		}
	}
}

// AddProof stores a proof from a node's event stream. A proof another node
// delivered before only gains the node in its SeenBy list.
func (s *Store) AddProof(envelope *Envelope, raw []byte, node string) (*ProofRecord, bool) {
	key := envelope.Key()
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.byKey[key]; existing != nil {
		if !slices.Contains(existing.SeenBy, node) {
			existing.SeenBy = append(existing.SeenBy, node)
			s.persistLocked()
		}
		return existing, false
	}
	if err := os.WriteFile(s.proofPath(key), raw, 0o644); err != nil {
		slog.Error("storing proof", "key", key, "err", err)
		return nil, false
	}
	_, viaGateway := s.submitted[key]
	record := &ProofRecord{
		Key:            key,
		Received:       time.Now().UTC(),
		BlockRoot:      "0x" + hexString(envelope.BeaconBlockRoot[:]),
		ProofType:      envelope.ProofType,
		ProofTypeName:  proofTypeName(envelope.ProofType),
		ValidatorIndex: envelope.ValidatorIndex,
		Size:           len(envelope.ProofData),
		ViaGateway:     viaGateway,
		SeenBy:         []string{node},
	}
	s.proofs = append([]*ProofRecord{record}, s.proofs...)
	s.byKey[key] = record
	for len(s.proofs) > s.keep {
		old := s.proofs[len(s.proofs)-1]
		s.proofs = s.proofs[:len(s.proofs)-1]
		delete(s.byKey, old.Key)
		if err := os.Remove(s.proofPath(old.Key)); err != nil && !os.IsNotExist(err) {
			slog.Warn("removing proof", "key", old.Key, "err", err)
		}
	}
	s.persistLocked()
	return record, true
}

// SetSlot records the slot of a proof's block.
func (s *Store) SetSlot(key string, slot uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.byKey[key]; p != nil {
		p.Slot = slot
		s.persistLocked()
	}
}

// AddSubmission records a submission.
func (s *Store) AddSubmission(sub *Submission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.submissions = append([]*Submission{sub}, s.submissions...)
	if len(s.submissions) > s.keep {
		s.submissions = s.submissions[:s.keep]
	}
	s.persistLocked()
}

// Proof returns a stored proof and its envelope JSON.
func (s *Store) Proof(key string) (*ProofRecord, []byte, bool) {
	s.mu.RLock()
	record := s.byKey[key]
	s.mu.RUnlock()
	if record == nil {
		return nil, nil, false
	}
	data, err := os.ReadFile(s.proofPath(key))
	if err != nil {
		return nil, nil, false
	}
	return record, data, true
}

// Snapshot returns copies of the proofs and submissions, newest first.
func (s *Store) Snapshot() ([]ProofRecord, []Submission) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	proofs := make([]ProofRecord, 0, len(s.proofs))
	for _, p := range s.proofs {
		copied := *p
		copied.SeenBy = slices.Clone(p.SeenBy)
		proofs = append(proofs, copied)
	}
	sort.SliceStable(proofs, func(i, j int) bool { return proofs[i].Received.After(proofs[j].Received) })
	submissions := make([]Submission, 0, len(s.submissions))
	for _, sub := range s.submissions {
		submissions = append(submissions, *sub)
	}
	return proofs, submissions
}

// persistLocked writes the state atomically. Caller holds the lock.
func (s *Store) persistLocked() {
	data, err := json.Marshal(state{Proofs: s.proofs, Submissions: s.submissions})
	if err != nil {
		slog.Error("encoding state", "err", err)
		return
	}
	tmp := filepath.Join(s.dir, "state.json.tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		slog.Error("writing state", "err", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, "state.json")); err != nil {
		slog.Error("writing state", "err", err)
	}
}
