package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testEnvelope(proofType uint8, prover uint64, size int) *Envelope {
	e := &Envelope{ProofType: proofType, ValidatorIndex: prover, ProofData: make([]byte, size)}
	for i := range e.ProofData {
		e.ProofData[i] = byte(i)
	}
	e.BeaconBlockRoot[0] = 0xab
	e.Signature[0] = 0xcd
	return e
}

func encodeList(envelopes ...*Envelope) []byte {
	var head, tail bytes.Buffer
	offset := 4 * len(envelopes)
	for _, e := range envelopes {
		_ = binary.Write(&head, binary.LittleEndian, uint32(offset))
		encoded := e.MarshalSSZ()
		tail.Write(encoded)
		offset += len(encoded)
	}
	return append(head.Bytes(), tail.Bytes()...)
}

func TestEnvelopeCodecs(t *testing.T) {
	e := testEnvelope(5, 1234, 10)

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Envelope
	if err := json.Unmarshal(data, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if fromJSON.Key() != e.Key() || !bytes.Equal(fromJSON.ProofData, e.ProofData) || fromJSON.Signature != e.Signature {
		t.Fatalf("json round trip: %+v", fromJSON)
	}

	// proof_type as bare number (Lighthouse) and quoted (Prysm)
	bare := strings.Replace(string(data), `"proof_type":"5"`, `"proof_type":5`, 1)
	var fromBare Envelope
	if err := json.Unmarshal([]byte(bare), &fromBare); err != nil || fromBare.ProofType != 5 {
		t.Fatalf("bare proof_type: %v %d", err, fromBare.ProofType)
	}

	list, err := DecodeEnvelopeList(encodeList(e, testEnvelope(2, 7, 3)))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Key() != e.Key() || !bytes.Equal(list[0].ProofData, e.ProofData) || list[1].ValidatorIndex != 7 {
		t.Fatalf("ssz list: %+v", list)
	}

	if _, err := DecodeEnvelopeList(encodeList(e, e, e, e, e)); err == nil {
		t.Fatal("more than 4 envelopes accepted")
	}
	if _, err := DecodeEnvelopeList([]byte{1, 2, 3, 4, 5}); err == nil {
		t.Fatal("garbage accepted")
	}
}

// fakeNode is a beacon node answering submissions with a fixed verdict and
// emitting accepted proofs on its event stream.
type fakeNode struct {
	server   *httptest.Server
	rejectAt map[int]string
	status   int

	mu     sync.Mutex
	events chan []byte
	got    int
}

func newFakeNode(t *testing.T, status int, rejectAt map[int]string) *fakeNode {
	n := &fakeNode{status: status, rejectAt: rejectAt, events: make(chan []byte, 16)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /eth/v1/beacon/execution_proofs", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var envelopes []json.RawMessage
		if err := json.Unmarshal(body, &envelopes); err != nil {
			list, err := DecodeEnvelopeList(body)
			if err != nil {
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			for _, e := range list {
				data, _ := json.Marshal(e)
				envelopes = append(envelopes, data)
			}
		}
		n.mu.Lock()
		n.got++
		n.mu.Unlock()
		if n.status != http.StatusOK && n.status != http.StatusBadRequest {
			w.WriteHeader(n.status)
			return
		}
		var failures []failure
		for i, envelope := range envelopes {
			if message, ok := n.rejectAt[i]; ok {
				failures = append(failures, failure{Index: i, Message: message})
				continue
			}
			n.events <- envelope
		}
		if len(failures) > 0 {
			writeJSON(w, http.StatusBadRequest, apiError{Code: 400, Message: "error processing execution proofs", Failures: failures})
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /eth/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case data := <-n.events:
				fmt.Fprintf(w, "event: execution_proof\ndata: %s\n\n", data)
				w.(http.Flusher).Flush()
			}
		}
	})
	mux.HandleFunc("GET /eth/v1/beacon/headers/{root}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"header":{"message":{"slot":"4242"}}}}`)
	})
	n.server = httptest.NewServer(mux)
	t.Cleanup(n.server.Close)
	return n
}

func newTestGateway(t *testing.T, nodes ...*fakeNode) (*Gateway, *httptest.Server) {
	store, err := NewStore(t.TempDir(), 3)
	if err != nil {
		t.Fatal(err)
	}
	page, err := template.New("page.html").Funcs(template.FuncMap{
		"short": func(s string) string { return s }, "size": func(n int) string { return fmt.Sprint(n) },
		"ago": func(time.Time) string { return "now" },
	}).ParseFS(pageFS, "page.html")
	if err != nil {
		t.Fatal(err)
	}
	g := &Gateway{store: store, page: page, network: "Test", explorerURL: "https://dora.example"}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for i, n := range nodes {
		node := NewBeacon(fmt.Sprintf("node%d", i+1), n.server.URL)
		g.nodes = append(g.nodes, node)
		go node.StreamProofs(ctx, func(data []byte) { g.handleEvent(ctx, node, data) })
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /eth/v1/beacon/execution_proofs", g.handleSubmit)
	mux.HandleFunc("GET /proofs/{file}", g.handleDownload)
	mux.HandleFunc("GET /{$}", g.handlePage)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	time.Sleep(100 * time.Millisecond) // event streams connect
	return g, server
}

func submit(t *testing.T, server *httptest.Server, contentType string, body []byte) (int, apiError) {
	t.Helper()
	resp, err := http.Post(server.URL+"/eth/v1/beacon/execution_proofs", contentType, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var apiErr apiError
	_ = json.NewDecoder(resp.Body).Decode(&apiErr)
	return resp.StatusCode, apiErr
}

func waitProofs(t *testing.T, g *Gateway, n int) []ProofRecord {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		proofs, _ := g.store.Snapshot()
		if len(proofs) == n || time.Now().After(deadline) {
			if len(proofs) != n {
				t.Fatalf("want %d proofs, have %d", n, len(proofs))
			}
			return proofs
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestGatewaySubmission(t *testing.T) {
	// node1 rejects the second proof, node2 accepts everything: both proofs are
	// accepted somewhere, so the client gets 200
	node1 := newFakeNode(t, http.StatusOK, map[int]string{1: "InvalidProof"})
	node2 := newFakeNode(t, http.StatusOK, nil)
	g, server := newTestGateway(t, node1, node2)

	a, b := testEnvelope(2, 11, 32), testEnvelope(5, 12, 64)
	body, _ := json.Marshal([]*Envelope{a, b})
	status, _ := submit(t, server, "application/json", body)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	proofs := waitProofs(t, g, 2)
	for _, p := range proofs {
		if !p.ViaGateway {
			t.Fatalf("proof %s not marked as submitted via the gateway", p.Key)
		}
	}
	_, subs := g.store.Snapshot()
	if len(subs) != 1 || subs[0].Status != 200 || subs[0].Nodes["node1"] != 400 || subs[0].Nodes["node2"] != 200 {
		t.Fatalf("submission record: %+v", subs)
	}
	if !subs[0].Proofs[1].Accepted || subs[0].Proofs[1].Errors != nil {
		t.Fatalf("proof accepted by node2 must count as accepted: %+v", subs[0].Proofs[1])
	}
	// both nodes delivered proof a; the record keeps both
	time.Sleep(100 * time.Millisecond)
	proofs, _ = g.store.Snapshot()
	for _, p := range proofs {
		if p.Key == a.Key() && len(p.SeenBy) != 2 {
			t.Fatalf("seen by: %v", p.SeenBy)
		}
		if p.Key == a.Key() && p.Slot != 4242 {
			t.Fatalf("slot: %d", p.Slot)
		}
	}

	// downloads
	resp, err := http.Get(server.URL + "/proofs/" + a.Key() + ".ssz")
	if err != nil {
		t.Fatal(err)
	}
	ssz, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(ssz, a.MarshalSSZ()) {
		t.Fatal("ssz download differs")
	}
	resp, _ = http.Get(server.URL + "/proofs/../state.json")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("path traversal: %d", resp.StatusCode)
	}

	// the page renders
	resp, _ = http.Get(server.URL + "/")
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(page), "via gateway") || !strings.Contains(string(page), "reth &#43; SP1") {
		t.Fatalf("page: %d", resp.StatusCode)
	}
}

func TestGatewayRejections(t *testing.T) {
	node1 := newFakeNode(t, http.StatusOK, map[int]string{0: "InvalidSignature"})
	node2 := newFakeNode(t, http.StatusServiceUnavailable, nil)
	g, server := newTestGateway(t, node1, node2)

	// SSZ submission rejected by the only answering node
	status, apiErr := submit(t, server, "application/octet-stream", encodeList(testEnvelope(3, 1, 8)))
	if status != http.StatusBadRequest || len(apiErr.Failures) != 1 || !strings.Contains(apiErr.Failures[0].Message, "node1: InvalidSignature") || !strings.Contains(apiErr.Failures[0].Message, "node2: status 503") {
		t.Fatalf("status %d: %+v", status, apiErr)
	}
	_, subs := g.store.Snapshot()
	if subs[0].Format != "ssz" || subs[0].Proofs[0].Accepted {
		t.Fatalf("submission: %+v", subs[0])
	}

	// undecodable bodies are not forwarded
	got := node1.got
	status, _ = submit(t, server, "application/json", []byte(`{"nope":1}`))
	if status != http.StatusBadRequest || node1.got != got {
		t.Fatalf("undecodable: %d", status)
	}

	// no node answering
	node1.status = http.StatusBadGateway
	status, _ = submit(t, server, "application/json", mustJSON([]*Envelope{testEnvelope(1, 1, 4)}))
	if status != http.StatusBadGateway {
		t.Fatalf("no node: %d", status)
	}
}

func TestStoreCap(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir, 2)
	for i := range 3 {
		e := testEnvelope(1, uint64(i), 4)
		data, _ := json.Marshal(e)
		store.AddProof(e, data, "n")
	}
	proofs, _ := store.Snapshot()
	if len(proofs) != 2 || proofs[0].ValidatorIndex != 2 {
		t.Fatalf("cap: %+v", proofs)
	}
	if _, _, ok := store.Proof(testEnvelope(1, 0, 4).Key()); ok {
		t.Fatal("evicted proof still downloadable")
	}
	reopened, _ := NewStore(dir, 2)
	if p, _ := reopened.Snapshot(); len(p) != 2 {
		t.Fatal("state not persisted")
	}
}

func mustJSON(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}
