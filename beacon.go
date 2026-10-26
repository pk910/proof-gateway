package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func hexString(data []byte) string { return hex.EncodeToString(data) }

// Beacon talks to one of the beacon nodes behind the gateway.
type Beacon struct {
	Name   string
	url    string
	client *http.Client
}

func NewBeacon(name string, url string) *Beacon {
	return &Beacon{Name: name, url: strings.TrimRight(url, "/"), client: &http.Client{Timeout: 2 * time.Minute}}
}

// BlockSlot returns the slot of a block.
func (b *Beacon) BlockSlot(ctx context.Context, root string) (uint64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url+"/eth/v1/beacon/headers/"+root, nil)
	if err != nil {
		return 0, err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	var header struct {
		Data struct {
			Header struct {
				Message struct {
					Slot string `json:"slot"`
				} `json:"message"`
			} `json:"header"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&header); err != nil {
		return 0, err
	}
	return strconv.ParseUint(header.Data.Header.Message.Slot, 10, 64)
}

// Submit forwards a proof submission and returns the node's response.
func (b *Beacon) Submit(ctx context.Context, body []byte, header http.Header) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url+"/eth/v1/beacon/execution_proofs", bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for _, name := range []string{"Content-Type", "Eth-Consensus-Version"} {
		if value := header.Get(name); value != "" {
			req.Header.Set(name, value)
		}
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, respBody, err
}

// StreamProofs follows the node's execution_proof event stream until ctx ends,
// reconnecting after errors, and hands each event's data to handle.
func (b *Beacon) StreamProofs(ctx context.Context, handle func(data []byte)) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := b.streamOnce(ctx, handle)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		slog.Warn("event stream ended, reconnecting", "node", b.Name, "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func (b *Beacon) streamOnce(ctx context.Context, handle func(data []byte)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url+"/eth/v1/events?topics=execution_proof", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	slog.Info("event stream connected", "node", b.Name)

	scanner := bufio.NewScanner(resp.Body)
	// a proof is up to 4 MiB, 8 MiB as hex, in one data line
	scanner.Buffer(make([]byte, 64<<10), 12<<20)
	var event string
	var data bytes.Buffer
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if event == "execution_proof" && data.Len() > 0 {
				handle(bytes.Clone(data.Bytes()))
			}
			event = ""
			data.Reset()
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}
