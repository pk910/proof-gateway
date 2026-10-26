// Command proof-gateway is a public front for EIP-8025 execution proof
// submissions: it forwards submitted proofs to a set of beacon nodes, follows
// their execution_proof event streams and serves a landing page with the API
// description and the most recent proofs.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed page.html
var pageFS embed.FS

// set at build time (see Makefile)
var (
	BuildVersion string
	BuildTime    string
	BuildRelease string
)

func version() string {
	v := strings.Trim(BuildRelease, `"`)
	if v == "" {
		v = "dev"
	}
	if commit := strings.Trim(BuildVersion, `"`); commit != "" {
		v += " (" + commit + ")"
	}
	return v
}

// maxBodySize bounds a submission: 4 proofs of 4 MiB, as hex JSON.
const maxBodySize = 40 << 20

type beaconFlags []string

func (f *beaconFlags) String() string     { return strings.Join(*f, ",") }
func (f *beaconFlags) Set(v string) error { *f = append(*f, v); return nil }

type Gateway struct {
	nodes       []*Beacon
	store       *Store
	page        *template.Template
	network     string
	publicURL   string
	explorerURL string
}

func main() {
	var beacons beaconFlags
	flag.Var(&beacons, "beacon", "beacon node as [name=]url; repeat for several nodes")
	listen := flag.String("listen", ":8080", "listen address")
	dataDir := flag.String("data", "./data", "data directory")
	keep := flag.Int("keep", 100, "number of proofs and submissions kept")
	network := flag.String("network", "Sepolia", "network name shown on the page")
	publicURL := flag.String("public-url", "", "public base URL shown in the API examples")
	explorerURL := flag.String("explorer-url", "", "explorer base URL for slot links (dora)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("proof-gateway", version())
		return
	}

	if len(beacons) == 0 {
		slog.Error("at least one -beacon is required")
		os.Exit(2)
	}
	nodes := make([]*Beacon, 0, len(beacons))
	for _, spec := range beacons {
		name, endpoint, ok := strings.Cut(spec, "=")
		if !ok {
			endpoint = spec
			u, err := url.Parse(spec)
			if err != nil {
				slog.Error("invalid -beacon", "value", spec, "err", err)
				os.Exit(2)
			}
			name = u.Host
		}
		nodes = append(nodes, NewBeacon(name, endpoint))
	}

	store, err := NewStore(*dataDir, *keep)
	if err != nil {
		slog.Error("opening store", "err", err)
		os.Exit(1)
	}
	page, err := template.New("page.html").Funcs(template.FuncMap{
		"short": func(s string) string {
			if len(s) <= 14 {
				return s
			}
			return s[:8] + "…" + s[len(s)-4:]
		},
		"size": func(n int) string {
			switch {
			case n >= 1<<20:
				return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20))
			case n >= 1<<10:
				return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
			}
			return fmt.Sprintf("%d B", n)
		},
		"ago": func(t time.Time) string {
			d := time.Since(t).Round(time.Second)
			switch {
			case d < time.Minute:
				return fmt.Sprintf("%ds ago", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			case d < 48*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			}
			return fmt.Sprintf("%dd ago", int(d.Hours()/24))
		},
	}).ParseFS(pageFS, "page.html")
	if err != nil {
		slog.Error("parsing page", "err", err)
		os.Exit(1)
	}

	g := &Gateway{
		nodes:       nodes,
		store:       store,
		page:        page,
		network:     *network,
		publicURL:   strings.TrimRight(*publicURL, "/"),
		explorerURL: strings.TrimRight(*explorerURL, "/"),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for _, node := range nodes {
		go node.StreamProofs(ctx, func(data []byte) { g.handleEvent(ctx, node, data) })
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /eth/v1/beacon/execution_proofs", g.handleSubmit)
	mux.HandleFunc("GET /proofs/{file}", g.handleDownload)
	mux.HandleFunc("GET /api/proofs", g.handleAPIProofs)
	mux.HandleFunc("GET /api/submissions", g.handleAPISubmissions)
	mux.HandleFunc("GET /{$}", g.handlePage)

	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.Info("listening", "addr", *listen, "nodes", len(nodes), "version", version())
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server", "err", err)
		os.Exit(1)
	}
}

// handleEvent stores a proof delivered by a node's event stream.
func (g *Gateway) handleEvent(ctx context.Context, node *Beacon, data []byte) {
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		slog.Warn("undecodable execution_proof event", "node", node.Name, "err", err)
		return
	}
	record, created := g.store.AddProof(&envelope, data, node.Name)
	if !created || record == nil {
		return
	}
	slog.Info("proof", "node", node.Name, "key", record.Key, "type", record.ProofTypeName, "size", record.Size, "via_gateway", record.ViaGateway)
	go func() {
		for _, n := range append([]*Beacon{node}, g.nodes...) {
			lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			slot, err := n.BlockSlot(lookupCtx, record.BlockRoot)
			cancel()
			if err == nil {
				g.store.SetSlot(record.Key, slot)
				return
			}
		}
	}()
}

type failure struct {
	Index   int    `json:"index"`
	Message string `json:"message"`
}

type apiError struct {
	Code     int       `json:"code"`
	Message  string    `json:"message"`
	Failures []failure `json:"failures,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type nodeResult struct {
	node   *Beacon
	status int
	body   []byte
	err    error
}

// handleSubmit forwards a submission to every node. A proof counts as accepted
// once one node accepted it; the client gets 200 when every proof was accepted
// somewhere, else the failures of the proofs no node accepted.
func (g *Gateway) handleSubmit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, apiError{Code: 413, Message: "request body too large"})
		return
	}

	sub := &Submission{Time: time.Now().UTC(), Format: "json", Nodes: map[string]int{}}
	var envelopes []*Envelope
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/octet-stream") {
		sub.Format = "ssz"
		envelopes, err = DecodeEnvelopeList(body)
	} else {
		err = json.Unmarshal(body, &envelopes)
	}
	switch {
	case err != nil:
		sub.Status = http.StatusBadRequest
		sub.Error = "undecodable: " + err.Error()
		g.store.AddSubmission(sub)
		writeJSON(w, http.StatusBadRequest, apiError{Code: 400, Message: "invalid " + sub.Format + ": " + err.Error()})
		return
	case len(envelopes) == 0 || len(envelopes) > maxProofsPerRequest:
		sub.Status = http.StatusBadRequest
		sub.Error = fmt.Sprintf("%d proofs (1 to %d allowed)", len(envelopes), maxProofsPerRequest)
		g.store.AddSubmission(sub)
		writeJSON(w, http.StatusBadRequest, apiError{Code: 400, Message: sub.Error})
		return
	}

	keys := make([]string, len(envelopes))
	for i, envelope := range envelopes {
		keys[i] = envelope.Key()
		sub.Proofs = append(sub.Proofs, SubmittedProof{
			Key:            keys[i],
			BlockRoot:      "0x" + hexString(envelope.BeaconBlockRoot[:]),
			ProofType:      envelope.ProofType,
			ProofTypeName:  proofTypeName(envelope.ProofType),
			ValidatorIndex: envelope.ValidatorIndex,
			Size:           len(envelope.ProofData),
			Errors:         map[string]string{},
		})
	}
	// the nodes emit a proof on their event stream while verifying it, before
	// the submission returns
	g.store.MarkSubmitted(keys)

	results := make([]nodeResult, len(g.nodes))
	var wg sync.WaitGroup
	for i, node := range g.nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Minute)
			defer cancel()
			status, _, respBody, err := node.Submit(ctx, body, r.Header)
			results[i] = nodeResult{node: node, status: status, body: respBody, err: err}
		}()
	}
	wg.Wait()

	answered := false
	for _, res := range results {
		sub.Nodes[res.node.Name] = res.status
		switch {
		case res.err != nil:
			for i := range sub.Proofs {
				sub.Proofs[i].Errors[res.node.Name] = "unreachable: " + res.err.Error()
			}
		case res.status == http.StatusOK:
			answered = true
			for i := range sub.Proofs {
				sub.Proofs[i].Accepted = true
			}
		case res.status == http.StatusBadRequest:
			answered = true
			var nodeErr apiError
			_ = json.Unmarshal(res.body, &nodeErr)
			failed := map[int]string{}
			for _, f := range nodeErr.Failures {
				failed[f.Index] = f.Message
			}
			for i := range sub.Proofs {
				message, isFailed := failed[i]
				switch {
				case len(nodeErr.Failures) == 0:
					// a request-level rejection
					sub.Proofs[i].Errors[res.node.Name] = nodeErr.Message
				case isFailed:
					sub.Proofs[i].Errors[res.node.Name] = message
				default:
					sub.Proofs[i].Accepted = true
				}
			}
		default:
			message := fmt.Sprintf("status %d", res.status)
			var nodeErr apiError
			if json.Unmarshal(res.body, &nodeErr) == nil && nodeErr.Message != "" {
				message += ": " + nodeErr.Message
			}
			for i := range sub.Proofs {
				sub.Proofs[i].Errors[res.node.Name] = message
			}
		}
	}
	for i := range sub.Proofs {
		if sub.Proofs[i].Accepted || len(sub.Proofs[i].Errors) == 0 {
			sub.Proofs[i].Errors = nil
		}
	}

	var failures []failure
	for i, proof := range sub.Proofs {
		if proof.Accepted {
			continue
		}
		var messages []string
		for _, node := range g.nodes {
			if message, ok := proof.Errors[node.Name]; ok {
				messages = append(messages, node.Name+": "+message)
			}
		}
		failures = append(failures, failure{Index: i, Message: strings.Join(messages, "; ")})
	}

	switch {
	case !answered:
		sub.Status = http.StatusBadGateway
		sub.Error = "no beacon node answered"
		writeJSON(w, http.StatusBadGateway, apiError{Code: 502, Message: sub.Error, Failures: failures})
	case len(failures) > 0:
		sub.Status = http.StatusBadRequest
		writeJSON(w, http.StatusBadRequest, apiError{Code: 400, Message: "error processing execution proofs", Failures: failures})
	default:
		sub.Status = http.StatusOK
		w.WriteHeader(http.StatusOK)
	}
	g.store.AddSubmission(sub)
	slog.Info("submission", "proofs", len(sub.Proofs), "status", sub.Status, "format", sub.Format)
}

// handleDownload serves a stored proof as JSON or SSZ envelope.
func (g *Gateway) handleDownload(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	key, ext, _ := strings.Cut(file, ".")
	record, data, ok := g.store.Proof(key)
	if !ok {
		http.NotFound(w, r)
		return
	}
	name := fmt.Sprintf("proof-%s-type%d-prover%d", record.BlockRoot, record.ProofType, record.ValidatorIndex)
	switch ext {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+name+".json")
		_, _ = w.Write(data)
	case "ssz":
		var envelope Envelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			http.Error(w, "stored proof unreadable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+name+".ssz")
		_, _ = w.Write(envelope.MarshalSSZ())
	default:
		http.NotFound(w, r)
	}
}

func (g *Gateway) handleAPIProofs(w http.ResponseWriter, _ *http.Request) {
	proofs, _ := g.store.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"data": proofs})
}

func (g *Gateway) handleAPISubmissions(w http.ResponseWriter, _ *http.Request) {
	_, submissions := g.store.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"data": submissions})
}

func (g *Gateway) handlePage(w http.ResponseWriter, r *http.Request) {
	proofs, submissions := g.store.Snapshot()
	nodes := make([]string, len(g.nodes))
	for i, node := range g.nodes {
		nodes[i] = node.Name
	}
	base := g.publicURL
	if base == "" {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := g.page.Execute(w, map[string]any{
		"Network":     g.network,
		"BaseURL":     base,
		"ExplorerURL": g.explorerURL,
		"Nodes":       nodes,
		"Proofs":      proofs,
		"Submissions": submissions,
		"TypeNames":   proofTypeNames,
		"Version":     version(),
	})
	if err != nil {
		slog.Error("rendering page", "err", err)
	}
}
