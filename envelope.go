package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxProofSize is the EIP-8025 MAX_PROOF_SIZE.
const maxProofSize = 4 << 20

// maxProofsPerRequest is MAX_EXECUTION_PROOFS_PER_PAYLOAD, the bound of the
// envelope list the submission route takes.
const maxProofsPerRequest = 4

// Envelope is a SignedExecutionProofEnvelope.
type Envelope struct {
	ProofData       []byte
	ProofType       uint8
	BeaconBlockRoot [32]byte
	ValidatorIndex  uint64
	Signature       [96]byte
}

// Key identifies a proof: block, proof type and prover, as the gossip rules do.
func (e *Envelope) Key() string {
	return fmt.Sprintf("0x%x-%d-%d", e.BeaconBlockRoot[:], e.ProofType, e.ValidatorIndex)
}

type envelopeJSON struct {
	Message struct {
		ProofData       string          `json:"proof_data"`
		ProofType       json.RawMessage `json:"proof_type"`
		BeaconBlockRoot string          `json:"beacon_block_root"`
	} `json:"message"`
	ValidatorIndex json.RawMessage `json:"validator_index"`
	Signature      string          `json:"signature"`
}

// parseUint reads a JSON number or a quoted decimal.
func parseUint(raw json.RawMessage, bits int) (uint64, error) {
	text := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	return strconv.ParseUint(text, 10, bits)
}

func decodeHex(text string, size int) ([]byte, error) {
	data, err := hex.DecodeString(strings.TrimPrefix(text, "0x"))
	if err != nil {
		return nil, err
	}
	if size >= 0 && len(data) != size {
		return nil, fmt.Errorf("expected %d bytes, got %d", size, len(data))
	}
	return data, nil
}

// UnmarshalJSON decodes the beacon API form of the envelope.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	var raw envelopeJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	proofData, err := decodeHex(raw.Message.ProofData, -1)
	if err != nil {
		return fmt.Errorf("proof_data: %w", err)
	}
	if len(proofData) == 0 || len(proofData) > maxProofSize {
		return fmt.Errorf("proof_data: invalid size %d", len(proofData))
	}
	proofType, err := parseUint(raw.Message.ProofType, 8)
	if err != nil {
		return fmt.Errorf("proof_type: %w", err)
	}
	root, err := decodeHex(raw.Message.BeaconBlockRoot, 32)
	if err != nil {
		return fmt.Errorf("beacon_block_root: %w", err)
	}
	validatorIndex, err := parseUint(raw.ValidatorIndex, 64)
	if err != nil {
		return fmt.Errorf("validator_index: %w", err)
	}
	signature, err := decodeHex(raw.Signature, 96)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}

	e.ProofData = proofData
	e.ProofType = uint8(proofType)
	copy(e.BeaconBlockRoot[:], root)
	e.ValidatorIndex = validatorIndex
	copy(e.Signature[:], signature)
	return nil
}

// MarshalJSON encodes the beacon API form of the envelope.
func (e *Envelope) MarshalJSON() ([]byte, error) {
	var raw struct {
		Message struct {
			ProofData       string `json:"proof_data"`
			ProofType       string `json:"proof_type"`
			BeaconBlockRoot string `json:"beacon_block_root"`
		} `json:"message"`
		ValidatorIndex string `json:"validator_index"`
		Signature      string `json:"signature"`
	}
	raw.Message.ProofData = "0x" + hex.EncodeToString(e.ProofData)
	raw.Message.ProofType = strconv.FormatUint(uint64(e.ProofType), 10)
	raw.Message.BeaconBlockRoot = "0x" + hex.EncodeToString(e.BeaconBlockRoot[:])
	raw.ValidatorIndex = strconv.FormatUint(e.ValidatorIndex, 10)
	raw.Signature = "0x" + hex.EncodeToString(e.Signature[:])
	return json.Marshal(raw)
}

// SSZ layout:
//
//	ExecutionProofEnvelope       { proof_data: offset, proof_type: uint8, beacon_block_root: Bytes32 } + proof_data
//	SignedExecutionProofEnvelope { message: offset, validator_index: uint64, signature: Bytes96 } + message
const (
	messageFixedSize = 4 + 1 + 32
	signedFixedSize  = 4 + 8 + 96
)

// MarshalSSZ encodes the envelope as SSZ.
func (e *Envelope) MarshalSSZ() []byte {
	buf := make([]byte, signedFixedSize+messageFixedSize+len(e.ProofData))
	binary.LittleEndian.PutUint32(buf[0:4], signedFixedSize)
	binary.LittleEndian.PutUint64(buf[4:12], e.ValidatorIndex)
	copy(buf[12:108], e.Signature[:])
	msg := buf[signedFixedSize:]
	binary.LittleEndian.PutUint32(msg[0:4], messageFixedSize)
	msg[4] = e.ProofType
	copy(msg[5:37], e.BeaconBlockRoot[:])
	copy(msg[messageFixedSize:], e.ProofData)
	return buf
}

// UnmarshalSSZ decodes one SSZ-encoded envelope.
func (e *Envelope) UnmarshalSSZ(buf []byte) error {
	if len(buf) < signedFixedSize+messageFixedSize {
		return errors.New("envelope too short")
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != signedFixedSize {
		return errors.New("invalid message offset")
	}
	msg := buf[signedFixedSize:]
	if binary.LittleEndian.Uint32(msg[0:4]) != messageFixedSize {
		return errors.New("invalid proof_data offset")
	}
	proofData := msg[messageFixedSize:]
	if len(proofData) == 0 || len(proofData) > maxProofSize {
		return fmt.Errorf("invalid proof_data size %d", len(proofData))
	}
	e.ValidatorIndex = binary.LittleEndian.Uint64(buf[4:12])
	copy(e.Signature[:], buf[12:108])
	e.ProofType = msg[4]
	copy(e.BeaconBlockRoot[:], msg[5:37])
	e.ProofData = append([]byte(nil), proofData...)
	return nil
}

// DecodeEnvelopeList decodes an SSZ List[SignedExecutionProofEnvelope, 4].
func DecodeEnvelopeList(buf []byte) ([]*Envelope, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	if len(buf) < 4 {
		return nil, errors.New("list too short")
	}
	first := binary.LittleEndian.Uint32(buf[0:4])
	if first%4 != 0 || first == 0 || int(first) > len(buf) {
		return nil, errors.New("invalid first offset")
	}
	count := int(first / 4)
	if count > maxProofsPerRequest {
		return nil, fmt.Errorf("too many envelopes: %d", count)
	}
	offsets := make([]int, count+1)
	for i := range count {
		offsets[i] = int(binary.LittleEndian.Uint32(buf[i*4:]))
	}
	offsets[count] = len(buf)
	envelopes := make([]*Envelope, 0, count)
	for i := range count {
		if offsets[i] > offsets[i+1] || offsets[i+1] > len(buf) {
			return nil, errors.New("invalid offsets")
		}
		envelope := &Envelope{}
		if err := envelope.UnmarshalSSZ(buf[offsets[i]:offsets[i+1]]); err != nil {
			return nil, fmt.Errorf("envelope %d: %w", i, err)
		}
		envelopes = append(envelopes, envelope)
	}
	return envelopes, nil
}

// proofTypeNames are the EIP-8025 proof type assignments.
var proofTypeNames = map[uint8]string{
	1: "ethrex + OpenVM",
	2: "ethrex + SP1",
	3: "ethrex + Zisk",
	4: "reth + OpenVM",
	5: "reth + SP1",
	6: "reth + Zisk",
	7: "zesu + Zisk",
}

func proofTypeName(proofType uint8) string {
	if name, ok := proofTypeNames[proofType]; ok {
		return name
	}
	return fmt.Sprintf("unassigned #%d", proofType)
}
