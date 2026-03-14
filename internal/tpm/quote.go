// TPM Quote operations for clock capture and co-location binding.
//
// TPM2_Quote produces a signed attestation structure (TPMS_ATTEST) that
// includes the current values of selected PCRs, a caller-provided
// qualifying-data nonce, and -- critically -- the TPM's TPMS_CLOCK_INFO.
//
// The clock info contains a monotonic millisecond counter and a reset
// counter, both signed by the AK in hardware. This is the foundation
// of the co-location binding protocol: the server compares clock
// snapshots taken before and after a PIV operation to determine whether
// the YubiKey was physically local or remote.
//
// DOES NOT REQUIRE ELEVATION: Uses the same AK created during enrollment
// with UserWithAuth=true and empty auth.

package tpm

import (
  "encoding/base64"
  "encoding/binary"
  "fmt"

  "github.com/google/go-tpm/tpm2"
  "github.com/google/go-tpm/tpm2/transport"
)

// QuoteClockResult holds the parsed output of a TPM Quote focused on
// clock capture. The raw TPMS_ATTEST is preserved for server-side
// signature verification.
type QuoteClockResult struct {
  QuotedBase64   string `json:"quoted_b64"`
  SignatureBase64 string `json:"signature_b64"`
  ClockMilliseconds uint64 `json:"clock_ms"`
  ResetCount      uint32 `json:"reset_count"`
  RestartCount    uint32 `json:"restart_count"`
  ClockSafe       bool   `json:"safe"`
  PCR16ValueBase64 string `json:"pcr16_value_b64,omitempty"`
}

// PerformQuoteForClockCapture executes TPM2_Quote with the given
// qualifying data and returns the signed attestation plus parsed
// clock info. PCR selection includes banks 0-7 (platform) in SHA-256.
//
// Parameters:
//   - tpmTransport: open TPM connection
//   - akHandle: persistent handle of the AK
//   - qualifyingDataBase64: base64-encoded qualifying data (nonce)
func PerformQuoteForClockCapture(
  tpmTransport transport.TPMCloser,
  akHandle uint32,
  qualifyingDataBase64 string,
) (*QuoteClockResult, error) {
  qualifyingBytes, err := base64.StdEncoding.DecodeString(qualifyingDataBase64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 qualifying data: %w", err)
  }

  readPubResp, err := tpm2.ReadPublic{
    ObjectHandle: tpm2.TPMHandle(akHandle),
  }.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not read AK public area (handle 0x%08X): %w", akHandle, err)
  }

  quoteCmd := tpm2.Quote{
    SignHandle: tpm2.NamedHandle{
      Handle: tpm2.TPMHandle(akHandle),
      Name:   readPubResp.Name,
    },
    QualifyingData: tpm2.TPM2BData{Buffer: qualifyingBytes},
    InScheme: tpm2.TPMTSigScheme{
      Scheme: tpm2.TPMAlgRSASSA,
      Details: tpm2.NewTPMUSigScheme(
        tpm2.TPMAlgRSASSA,
        &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
      ),
    },
    PCRSelect: tpm2.TPMLPCRSelection{
      PCRSelections: []tpm2.TPMSPCRSelection{
        {
          Hash:      tpm2.TPMAlgSHA256,
          PCRSelect: tpm2.PCClientCompatible.PCRs(0, 1, 2, 3, 4, 5, 6, 7),
        },
      },
    },
  }

  quoteResp, err := quoteCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_Quote failed: %w", err)
  }

  quotedBytes := quoteResp.Quoted.Bytes()
  quotedB64 := base64.StdEncoding.EncodeToString(quotedBytes)

  rsaSig, err := quoteResp.Signature.Signature.RSASSA()
  if err != nil {
    return nil, fmt.Errorf("could not extract RSASSA signature from Quote: %w", err)
  }
  sigB64 := base64.StdEncoding.EncodeToString(rsaSig.Sig.Buffer)

  clockMs, resetCount, restartCount, clockSafe, err := parseClockInfoFromTPMSAttest(quotedBytes)
  if err != nil {
    return nil, fmt.Errorf("could not parse clock info from TPMS_ATTEST: %w", err)
  }

  return &QuoteClockResult{
    QuotedBase64:      quotedB64,
    SignatureBase64:   sigB64,
    ClockMilliseconds: clockMs,
    ResetCount:        resetCount,
    RestartCount:      restartCount,
    ClockSafe:         clockSafe,
  }, nil
}

// ExtendPCRAndQuote extends the given PCR with the provided data,
// then immediately performs a Quote. This is used in Phase 3 of
// co-location binding: extend PCR 16 with SHA256(S2), then quote
// with qualifying data = (N1 || S1 || S2).
//
// Parameters:
//   - tpmTransport: open TPM connection
//   - akHandle: persistent handle of the AK
//   - pcrIndex: PCR register to extend (typically 16 for application use)
//   - extendDataBase64: base64-encoded hash to extend into the PCR
//   - qualifyingDataBase64: base64-encoded qualifying data for the Quote
func ExtendPCRAndQuote(
  tpmTransport transport.TPMCloser,
  akHandle uint32,
  pcrIndex int,
  extendDataBase64 string,
  qualifyingDataBase64 string,
) (*QuoteClockResult, error) {
  extendBytes, err := base64.StdEncoding.DecodeString(extendDataBase64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 extend data: %w", err)
  }
  if len(extendBytes) != 32 {
    return nil, fmt.Errorf("extend data must be exactly 32 bytes (SHA-256 hash), got %d", len(extendBytes))
  }

  qualifyingBytes, err := base64.StdEncoding.DecodeString(qualifyingDataBase64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 qualifying data: %w", err)
  }

  pcrExtendCmd := tpm2.PCRExtend{
    PCRHandle: tpm2.AuthHandle{
      Handle: tpm2.TPMHandle(pcrIndex),
      Auth:   tpm2.PasswordAuth(nil),
    },
    Digests: tpm2.TPMLDigestValues{
      Digests: []tpm2.TPMTHA{
        {
          HashAlg: tpm2.TPMAlgSHA256,
          Digest:  extendBytes,
        },
      },
    },
  }
  if _, err := pcrExtendCmd.Execute(tpmTransport); err != nil {
    return nil, fmt.Errorf("TPM2_PCR_Extend on PCR %d failed: %w", pcrIndex, err)
  }

  readPubResp, err := tpm2.ReadPublic{
    ObjectHandle: tpm2.TPMHandle(akHandle),
  }.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not read AK public area (handle 0x%08X): %w", akHandle, err)
  }

  quoteCmd := tpm2.Quote{
    SignHandle: tpm2.NamedHandle{
      Handle: tpm2.TPMHandle(akHandle),
      Name:   readPubResp.Name,
    },
    QualifyingData: tpm2.TPM2BData{Buffer: qualifyingBytes},
    InScheme: tpm2.TPMTSigScheme{
      Scheme: tpm2.TPMAlgRSASSA,
      Details: tpm2.NewTPMUSigScheme(
        tpm2.TPMAlgRSASSA,
        &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
      ),
    },
    PCRSelect: tpm2.TPMLPCRSelection{
      PCRSelections: []tpm2.TPMSPCRSelection{
        {
          Hash:      tpm2.TPMAlgSHA256,
          PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcrIndex)),
        },
      },
    },
  }

  quoteResp, err := quoteCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_Quote failed: %w", err)
  }

  quotedBytes := quoteResp.Quoted.Bytes()
  quotedB64 := base64.StdEncoding.EncodeToString(quotedBytes)

  rsaSig, err := quoteResp.Signature.Signature.RSASSA()
  if err != nil {
    return nil, fmt.Errorf("could not extract RSASSA signature from Quote: %w", err)
  }
  sigB64 := base64.StdEncoding.EncodeToString(rsaSig.Sig.Buffer)

  clockMs, resetCount, restartCount, clockSafe, err := parseClockInfoFromTPMSAttest(quotedBytes)
  if err != nil {
    return nil, fmt.Errorf("could not parse clock info from TPMS_ATTEST: %w", err)
  }

  pcrReadCmd := tpm2.PCRRead{
    PCRSelectionIn: tpm2.TPMLPCRSelection{
      PCRSelections: []tpm2.TPMSPCRSelection{
        {
          Hash:      tpm2.TPMAlgSHA256,
          PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcrIndex)),
        },
      },
    },
  }
  pcrReadResp, err := pcrReadCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_PCR_Read for PCR %d failed: %w", pcrIndex, err)
  }

  pcr16ValueB64 := ""
  if len(pcrReadResp.PCRValues.Digests) > 0 {
    pcr16ValueB64 = base64.StdEncoding.EncodeToString(pcrReadResp.PCRValues.Digests[0].Buffer)
  }

  return &QuoteClockResult{
    QuotedBase64:      quotedB64,
    SignatureBase64:   sigB64,
    ClockMilliseconds: clockMs,
    ResetCount:        resetCount,
    RestartCount:      restartCount,
    ClockSafe:         clockSafe,
    PCR16ValueBase64:  pcr16ValueB64,
  }, nil
}

// parseClockInfoFromTPMSAttest extracts TPMS_CLOCK_INFO fields from a
// raw TPMS_ATTEST byte sequence. The structure layout (TPM 2.0 spec
// Part 2, section 10.12.8):
//
//   magic (4) + type (2) + qualifiedSigner (2+N) + extraData (2+N)
//   + clockInfo { clock(8) + resetCount(4) + restartCount(4) + safe(1) }
//
// All multi-byte integers are big-endian per TCG conventions.
func parseClockInfoFromTPMSAttest(attestBytes []byte) (clockMs uint64, resetCount uint32, restartCount uint32, safe bool, err error) {
  if len(attestBytes) < 10 {
    return 0, 0, 0, false, fmt.Errorf("TPMS_ATTEST too short (%d bytes)", len(attestBytes))
  }

  offset := 0

  offset += 4 // magic (TPM_GENERATED_VALUE)
  offset += 2 // type (TPMI_ST_ATTEST)

  if offset+2 > len(attestBytes) {
    return 0, 0, 0, false, fmt.Errorf("TPMS_ATTEST truncated at qualifiedSigner size")
  }
  qualifiedSignerSize := int(binary.BigEndian.Uint16(attestBytes[offset:]))
  offset += 2 + qualifiedSignerSize

  if offset+2 > len(attestBytes) {
    return 0, 0, 0, false, fmt.Errorf("TPMS_ATTEST truncated at extraData size")
  }
  extraDataSize := int(binary.BigEndian.Uint16(attestBytes[offset:]))
  offset += 2 + extraDataSize

  clockInfoSize := 8 + 4 + 4 + 1
  if offset+clockInfoSize > len(attestBytes) {
    return 0, 0, 0, false, fmt.Errorf("TPMS_ATTEST truncated at clockInfo (need %d bytes at offset %d, have %d)", clockInfoSize, offset, len(attestBytes))
  }

  clockMs = binary.BigEndian.Uint64(attestBytes[offset:])
  offset += 8
  resetCount = binary.BigEndian.Uint32(attestBytes[offset:])
  offset += 4
  restartCount = binary.BigEndian.Uint32(attestBytes[offset:])
  offset += 4
  safe = attestBytes[offset] != 0

  return clockMs, resetCount, restartCount, safe, nil
}
