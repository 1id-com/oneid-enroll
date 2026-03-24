// PIV-based key wrapping using ECDH-P256 + AES-256 Key Wrap (RFC 3394).
//
// Wrap: reads the PIV public key from slot 9d (Key Management), performs
// ECDH with a software-generated ephemeral key, derives an AES-256 KEK
// via NIST SP 800-56A Concat KDF, and wraps the plaintext using AES-KW.
//
// Unwrap: performs ECDH on the YubiKey hardware (via SharedKey on slot 9d),
// derives the same KEK, and AES-KW unwraps the ciphertext.
//
// The PIV private key never leaves the YubiKey. Only unwrap requires the
// hardware; wrap only needs the public key (which is read from the device).
//
// Slot 9d (Key Management) is the PIV-standard slot for key agreement
// and key transport operations, separate from slot 9a (Authentication)
// used for signing.
//
// No elevation required.

package piv

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "fmt"

  gopiv "github.com/go-piv/piv-go/piv"
)

// ecdh_kdf_application_label is the fixed info string used in the NIST
// SP 800-56A Concat KDF to derive the AES-256 KEK from the ECDH shared
// secret. Changing this value would break all previously wrapped keys.
const ecdh_kdf_application_label = "1id-piv-keywrap-v1"

// PIVKeyWrapResult holds the output of wrapping a key with PIV ECDH + AES-KW.
// Both the ephemeral public key and wrapped key are needed for unwrapping.
type PIVKeyWrapResult struct {
  EphemeralPublicKeyB64 string `json:"ephemeral_public_key_b64"`
  WrappedKeyB64         string `json:"wrapped_key_b64"`
  PIVDeviceSerial       string `json:"piv_device_serial"`
  PIVSlot               string `json:"piv_slot"`
  Algorithm             string `json:"algorithm"`
}

// PIVKeyUnwrapResult holds the recovered plaintext from a PIV unwrap.
type PIVKeyUnwrapResult struct {
  PlaintextKeyB64 string `json:"plaintext_key_b64"`
  PIVDeviceSerial string `json:"piv_device_serial"`
}

// derive_aes256_kek_via_concat_kdf derives a 32-byte AES-256 key from an
// ECDH shared secret using the NIST SP 800-56A single-pass Concat KDF.
//
// For 256-bit output, only one SHA-256 iteration is needed:
//
//	KEK = SHA-256(0x00000001 || Z || FixedInfo)
//
// where Z is the shared secret and FixedInfo is the application label.
func DeriveAES256KEKViaConcatKDF(ecdh_shared_secret_bytes []byte) []byte {
  hasher := sha256.New()
  hasher.Write([]byte{0x00, 0x00, 0x00, 0x01})
  hasher.Write(ecdh_shared_secret_bytes)
  hasher.Write([]byte(ecdh_kdf_application_label))
  return hasher.Sum(nil)
}

// pad_ecdh_shared_secret_to_32_bytes ensures the shared secret is exactly
// 32 bytes (the P-256 field element size). big.Int.Bytes() and the PIV
// hardware may strip leading zero bytes; this function restores them.
func PadECDHSharedSecretTo32Bytes(raw_shared_secret []byte) []byte {
  if len(raw_shared_secret) >= 32 {
    return raw_shared_secret
  }
  padded := make([]byte, 32)
  copy(padded[32-len(raw_shared_secret):], raw_shared_secret)
  return padded
}

// ensure_slot_9d_key_management_key_exists checks PIV slot 9d for an
// existing P-256 key. If none exists, generates a new one with
// pin-policy=NEVER and touch-policy=NEVER (required for autonomous
// agent operation).
//
// Returns the P-256 public key from slot 9d.
func ensure_slot_9d_key_management_key_exists(
  yubikey_connection *gopiv.YubiKey,
  management_key [24]byte,
) (*ecdsa.PublicKey, error) {
  slot_9d := gopiv.SlotKeyManagement

  attest_cert, attest_err := yubikey_connection.Attest(slot_9d)
  if attest_err == nil {
    ecdsa_pub, ok := attest_cert.PublicKey.(*ecdsa.PublicKey)
    if ok && ecdsa_pub.Curve == elliptic.P256() {
      return ecdsa_pub, nil
    }
  }

  stored_cert, cert_err := yubikey_connection.Certificate(slot_9d)
  if cert_err == nil {
    ecdsa_pub, ok := stored_cert.PublicKey.(*ecdsa.PublicKey)
    if ok && ecdsa_pub.Curve == elliptic.P256() {
      return ecdsa_pub, nil
    }
  }

  generated_pub, gen_err := yubikey_connection.GenerateKey(management_key, slot_9d, gopiv.Key{
    Algorithm:   gopiv.AlgorithmEC256,
    PINPolicy:   gopiv.PINPolicyNever,
    TouchPolicy: gopiv.TouchPolicyNever,
  })
  if gen_err != nil {
    return nil, fmt.Errorf("could not generate PIV key in slot 9d (Key Management): %w", gen_err)
  }

  ecdsa_pub, ok := generated_pub.(*ecdsa.PublicKey)
  if !ok {
    return nil, fmt.Errorf("generated key in slot 9d is not ECDSA (got %T)", generated_pub)
  }

  new_attest_cert, new_attest_err := yubikey_connection.Attest(slot_9d)
  if new_attest_err == nil {
    _ = yubikey_connection.SetCertificate(management_key, slot_9d, new_attest_cert)
  }

  return ecdsa_pub, nil
}

// WrapKeyWithPIV encrypts a key (DEK/MEK) using the PIV device's slot 9d key.
//
// Algorithm: ECDH-P256 + NIST-Concat-KDF + AES-256-KW (RFC 3394)
//
//  1. Reads the P-256 public key from slot 9d (auto-generates if absent)
//  2. Generates an ephemeral P-256 key pair in software
//  3. ECDH: shared_secret = ephemeral_private_scalar * piv_public_point
//  4. KDF: kek = SHA-256(0x00000001 || shared_secret || "1id-piv-keywrap-v1")
//  5. AES-KW: wrapped = AES-256-KeyWrap(kek, plaintext)
//
// plaintext_key_b64: base64-encoded key material to wrap (16-128 bytes,
// must be a multiple of 8 for AES-KW).
//
// Returns the ephemeral public key and wrapped ciphertext. Both are needed
// to unwrap. The ephemeral private key is securely discarded (never stored).
func WrapKeyWithPIV(plaintext_key_b64 string) (*PIVKeyWrapResult, error) {
  plaintext_bytes, err := base64.StdEncoding.DecodeString(plaintext_key_b64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in plaintext_key: %w", err)
  }
  if len(plaintext_bytes) < 16 {
    return nil, fmt.Errorf("plaintext key must be at least 16 bytes for AES Key Wrap (got %d)", len(plaintext_bytes))
  }
  if len(plaintext_bytes) > 128 {
    return nil, fmt.Errorf("plaintext key must be at most 128 bytes (got %d)", len(plaintext_bytes))
  }
  if len(plaintext_bytes)%8 != 0 {
    return nil, fmt.Errorf("plaintext key must be a multiple of 8 bytes for AES Key Wrap (got %d)", len(plaintext_bytes))
  }

  yubikey_connection, _, err := OpenFirstAvailablePIVDevice()
  if err != nil {
    return nil, err
  }
  defer yubikey_connection.Close()

  device_serial, err := yubikey_connection.Serial()
  if err != nil {
    return nil, fmt.Errorf("could not read PIV device serial number: %w", err)
  }

  piv_slot_9d_public_key, err := ensure_slot_9d_key_management_key_exists(yubikey_connection, DefaultManagementKey)
  if err != nil {
    return nil, err
  }

  ephemeral_private_key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    return nil, fmt.Errorf("could not generate ephemeral P-256 key: %w", err)
  }

  // ECDH in software: shared_point = ephemeral_private_scalar * piv_public_point
  shared_point_x, _ := piv_slot_9d_public_key.ScalarMult(
    piv_slot_9d_public_key.X,
    piv_slot_9d_public_key.Y,
    ephemeral_private_key.D.Bytes(),
  )
  shared_secret_bytes := PadECDHSharedSecretTo32Bytes(shared_point_x.Bytes())

  kek := DeriveAES256KEKViaConcatKDF(shared_secret_bytes)

  wrapped_key_bytes, err := AESKeyWrap(kek, plaintext_bytes)
  if err != nil {
    return nil, fmt.Errorf("AES Key Wrap failed: %w", err)
  }

  ephemeral_public_key_uncompressed_bytes := elliptic.Marshal(
    elliptic.P256(),
    ephemeral_private_key.PublicKey.X,
    ephemeral_private_key.PublicKey.Y,
  )

  return &PIVKeyWrapResult{
    EphemeralPublicKeyB64: base64.StdEncoding.EncodeToString(ephemeral_public_key_uncompressed_bytes),
    WrappedKeyB64:         base64.StdEncoding.EncodeToString(wrapped_key_bytes),
    PIVDeviceSerial:       fmt.Sprintf("%d", device_serial),
    PIVSlot:               "9d",
    Algorithm:             "ECDH-P256+AES256-KW",
  }, nil
}

// UnwrapKeyWithPIV decrypts a wrapped key using the PIV device's slot 9d key.
//
// The ECDH shared secret is computed on the YubiKey hardware via the
// ECDSAPrivateKey.SharedKey method -- the private key never leaves the device.
//
// ephemeral_public_key_b64: base64-encoded uncompressed P-256 point from WrapKeyWithPIV.
// wrapped_key_b64: base64-encoded AES-KW ciphertext from WrapKeyWithPIV.
func UnwrapKeyWithPIV(ephemeral_public_key_b64 string, wrapped_key_b64 string) (*PIVKeyUnwrapResult, error) {
  ephemeral_pub_bytes, err := base64.StdEncoding.DecodeString(ephemeral_public_key_b64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in ephemeral_public_key: %w", err)
  }
  wrapped_bytes, err := base64.StdEncoding.DecodeString(wrapped_key_b64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in wrapped_key: %w", err)
  }

  ephemeral_x, ephemeral_y := elliptic.Unmarshal(elliptic.P256(), ephemeral_pub_bytes)
  if ephemeral_x == nil {
    return nil, fmt.Errorf("invalid ephemeral public key: could not unmarshal P-256 uncompressed point")
  }
  ephemeral_public_key := &ecdsa.PublicKey{
    Curve: elliptic.P256(),
    X:     ephemeral_x,
    Y:     ephemeral_y,
  }

  yubikey_connection, _, err := OpenFirstAvailablePIVDevice()
  if err != nil {
    return nil, err
  }
  defer yubikey_connection.Close()

  device_serial, err := yubikey_connection.Serial()
  if err != nil {
    return nil, fmt.Errorf("could not read PIV device serial number: %w", err)
  }

  slot_9d := gopiv.SlotKeyManagement
  var slot_9d_public_key *ecdsa.PublicKey

  stored_cert, cert_err := yubikey_connection.Certificate(slot_9d)
  if cert_err == nil {
    ecdsa_key, ok := stored_cert.PublicKey.(*ecdsa.PublicKey)
    if ok {
      slot_9d_public_key = ecdsa_key
    }
  }
  if slot_9d_public_key == nil {
    attest_cert, attest_err := yubikey_connection.Attest(slot_9d)
    if attest_err != nil {
      return nil, fmt.Errorf("no key found in slot 9d (Key Management) -- wrap must be called first: %w", attest_err)
    }
    ecdsa_key, ok := attest_cert.PublicKey.(*ecdsa.PublicKey)
    if !ok {
      return nil, fmt.Errorf("slot 9d key is not ECDSA (got %T)", attest_cert.PublicKey)
    }
    slot_9d_public_key = ecdsa_key
  }

  private_key_interface, err := yubikey_connection.PrivateKey(
    slot_9d,
    slot_9d_public_key,
    gopiv.KeyAuth{},
  )
  if err != nil {
    return nil, fmt.Errorf("could not get private key handle for slot 9d: %w", err)
  }

  ecdsa_hardware_private_key, ok := private_key_interface.(*gopiv.ECDSAPrivateKey)
  if !ok {
    return nil, fmt.Errorf("slot 9d private key is not ECDSAPrivateKey (got %T); ECDH requires EC key", private_key_interface)
  }

  // ECDH on YubiKey hardware: shared_secret = piv_private_scalar * ephemeral_public_point
  raw_shared_secret, err := ecdsa_hardware_private_key.SharedKey(ephemeral_public_key)
  if err != nil {
    return nil, fmt.Errorf("ECDH SharedKey on YubiKey hardware failed: %w", err)
  }
  shared_secret_bytes := PadECDHSharedSecretTo32Bytes(raw_shared_secret)

  kek := DeriveAES256KEKViaConcatKDF(shared_secret_bytes)

  plaintext_bytes, err := AESKeyUnwrap(kek, wrapped_bytes)
  if err != nil {
    return nil, fmt.Errorf("AES Key Unwrap failed: %w", err)
  }

  return &PIVKeyUnwrapResult{
    PlaintextKeyB64: base64.StdEncoding.EncodeToString(plaintext_bytes),
    PIVDeviceSerial: fmt.Sprintf("%d", device_serial),
  }, nil
}
