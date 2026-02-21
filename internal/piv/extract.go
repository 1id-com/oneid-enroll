// PIV key generation and attestation extraction for YubiKey enrollment.
//
// The extract operation is the PIV equivalent of the TPM's EK+AK extraction:
// it ensures a signing key exists in PIV slot 9a (Authentication) and returns
// the attestation certificate chain that proves the key was generated on a
// genuine Yubico device.
//
// Key generation uses pin-policy=NEVER and touch-policy=NEVER so that AI
// agents can sign challenges autonomously without human interaction.
//
// No elevation required for any operation.

package piv

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/x509"
  "encoding/pem"
  "fmt"

  gopiv "github.com/go-piv/piv-go/piv"
)

// DefaultManagementKey is the factory default 3DES management key for YubiKeys.
// Used to authorize key generation and certificate storage operations.
var DefaultManagementKey = [24]byte{
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

// PIVExtractResult contains everything the server needs for YubiKey enrollment.
// Parallels the TPM ExtractAndGenerateAKResult but uses PIV attestation instead
// of TPM EK+AK credential activation.
type PIVExtractResult struct {
  AttestationCertPEM   string   `json:"attestation_cert_pem"`
  IntermediateCertPEM  string   `json:"intermediate_cert_pem"`
  AttestationChainPEM  []string `json:"attestation_chain_pem"`
  SigningKeyPublicPEM  string   `json:"signing_key_public_pem"`
  SerialNumber         string   `json:"serial_number"`
  FirmwareVersion      string   `json:"firmware_version"`
  SlotName             string   `json:"slot"`
  Algorithm            string   `json:"algorithm"`
  PINPolicy            string   `json:"pin_policy"`
  TouchPolicy          string   `json:"touch_policy"`
  KeyWasNewlyGenerated bool     `json:"key_was_newly_generated"`
}

// encode_certificate_to_pem_string converts a DER-encoded x509 certificate to PEM format.
func encode_certificate_to_pem_string(cert *x509.Certificate) string {
  return string(pem.EncodeToMemory(&pem.Block{
    Type:  "CERTIFICATE",
    Bytes: cert.Raw,
  }))
}

// encode_ecdsa_public_key_to_pem_string marshals an ECDSA public key to PEM.
func encode_ecdsa_public_key_to_pem_string(public_key *ecdsa.PublicKey) (string, error) {
  der_bytes, err := x509.MarshalPKIXPublicKey(public_key)
  if err != nil {
    return "", fmt.Errorf("could not marshal ECDSA public key to PKIX DER: %w", err)
  }
  return string(pem.EncodeToMemory(&pem.Block{
    Type:  "PUBLIC KEY",
    Bytes: der_bytes,
  })), nil
}

// ExtractPIVAttestationAndEnsureKeyExists opens the first available PIV device,
// ensures a signing key exists in slot 9a, and returns the attestation data
// needed for sovereign-portable enrollment.
//
// If slot 9a is empty, a new ECCP256 key is generated with pin-policy=NEVER
// and touch-policy=NEVER (critical for autonomous agent operation).
//
// If slot 9a already has a key with valid attestation, reuses it.
//
// The management_key parameter authorizes key generation. Pass DefaultManagementKey
// for factory-state devices.
//
// Returns the attestation cert (proves key was generated on-device),
// the F9 intermediate cert (proves device is genuine Yubico hardware),
// and the public key PEM.
func ExtractPIVAttestationAndEnsureKeyExists(management_key [24]byte) (*PIVExtractResult, error) {
  yubikey_connection, _, err := OpenFirstAvailablePIVDevice()
  if err != nil {
    return nil, err
  }
  defer yubikey_connection.Close()

  device_serial_number, err := yubikey_connection.Serial()
  if err != nil {
    return nil, fmt.Errorf("could not read device serial number: %w", err)
  }
  device_firmware_version := yubikey_connection.Version()

  // Check if slot 9a already has a key by trying to attest it.
  // Attest() creates an on-the-fly attestation cert signed by the F9 key,
  // which only succeeds if the key was generated on-device.
  slot_9a := gopiv.SlotAuthentication
  key_was_newly_generated := false
  slot_attestation_cert, attest_err := yubikey_connection.Attest(slot_9a)

  if attest_err != nil {
    // No attestable key in 9a -- generate a new one.
    // ECCP256 with pin-policy=NEVER, touch-policy=NEVER enables fully
    // autonomous operation (no human interaction for signing).
    _, gen_err := yubikey_connection.GenerateKey(management_key, slot_9a, gopiv.Key{
      Algorithm:   gopiv.AlgorithmEC256,
      PINPolicy:   gopiv.PINPolicyNever,
      TouchPolicy: gopiv.TouchPolicyNever,
    })
    if gen_err != nil {
      return nil, fmt.Errorf("could not generate PIV key in slot 9a: %w", gen_err)
    }
    key_was_newly_generated = true

    // Now attest the newly generated key
    slot_attestation_cert, err = yubikey_connection.Attest(slot_9a)
    if err != nil {
      return nil, fmt.Errorf("could not attest newly generated key in slot 9a: %w", err)
    }
  }

  // Get the F9 intermediate certificate (factory attestation key cert).
  // This cert, together with the Yubico PIV Root CA, forms the chain of trust.
  f9_intermediate_cert, err := yubikey_connection.AttestationCertificate()
  if err != nil {
    return nil, fmt.Errorf("could not read F9 attestation intermediate certificate: %w", err)
  }

  // Verify the attestation chain locally before returning it.
  // This uses go-piv's built-in Verify which checks that the slot cert
  // was signed by the F9 intermediate cert.
  verified_attestation, err := gopiv.Verify(f9_intermediate_cert, slot_attestation_cert)
  if err != nil {
    return nil, fmt.Errorf("local attestation chain verification failed: %w", err)
  }

  // Extract the public key from the attestation cert
  ecdsa_public_key, ok := slot_attestation_cert.PublicKey.(*ecdsa.PublicKey)
  if !ok {
    return nil, fmt.Errorf("attestation cert public key is not ECDSA (got %T)", slot_attestation_cert.PublicKey)
  }
  if ecdsa_public_key.Curve != elliptic.P256() {
    return nil, fmt.Errorf("expected P-256 curve, got %s", ecdsa_public_key.Curve.Params().Name)
  }

  public_key_pem, err := encode_ecdsa_public_key_to_pem_string(ecdsa_public_key)
  if err != nil {
    return nil, fmt.Errorf("could not encode public key to PEM: %w", err)
  }

  // Store the attestation cert in the slot so Certificate(slot) works for signing later
  set_cert_err := yubikey_connection.SetCertificate(management_key, slot_9a, slot_attestation_cert)
  if set_cert_err != nil {
    fmt.Printf("warning: could not store attestation cert in slot 9a: %v\n", set_cert_err)
  }

  attestation_cert_pem := encode_certificate_to_pem_string(slot_attestation_cert)
  intermediate_cert_pem := encode_certificate_to_pem_string(f9_intermediate_cert)

  pin_policy_string := "never"
  touch_policy_string := "never"
  if verified_attestation.PINPolicy == gopiv.PINPolicyAlways {
    pin_policy_string = "always"
  } else if verified_attestation.PINPolicy == gopiv.PINPolicyOnce {
    pin_policy_string = "once"
  }
  if verified_attestation.TouchPolicy == gopiv.TouchPolicyAlways {
    touch_policy_string = "always"
  } else if verified_attestation.TouchPolicy == gopiv.TouchPolicyCached {
    touch_policy_string = "cached"
  }

  return &PIVExtractResult{
    AttestationCertPEM:   attestation_cert_pem,
    IntermediateCertPEM:  intermediate_cert_pem,
    AttestationChainPEM:  []string{intermediate_cert_pem},
    SigningKeyPublicPEM:  public_key_pem,
    SerialNumber:         fmt.Sprintf("%d", device_serial_number),
    FirmwareVersion: fmt.Sprintf("%d.%d.%d",
      device_firmware_version.Major,
      device_firmware_version.Minor,
      device_firmware_version.Patch),
    SlotName:             "9a",
    Algorithm:            "ECCP256",
    PINPolicy:            pin_policy_string,
    TouchPolicy:          touch_policy_string,
    KeyWasNewlyGenerated: key_was_newly_generated,
  }, nil
}

