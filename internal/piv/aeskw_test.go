package piv

import (
  "bytes"
  "encoding/hex"
  "testing"
)

// RFC 3394 Section 4 test vectors -- all using 256-bit KEK since that
// matches our ECDH-derived key size.

func decode_hex_for_test(t *testing.T, hex_string string) []byte {
  t.Helper()
  decoded_bytes, err := hex.DecodeString(hex_string)
  if err != nil {
    t.Fatalf("invalid hex in test vector: %s", hex_string)
  }
  return decoded_bytes
}

// RFC 3394 Section 4.3: Wrap 128 bits of Key Data with a 256-bit KEK
func TestAESKeyWrap_RFC3394_Vector_4_3_Wrap_128bit_Key_With_256bit_KEK(t *testing.T) {
  kek := decode_hex_for_test(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
  plaintext := decode_hex_for_test(t, "00112233445566778899AABBCCDDEEFF")
  expected_ciphertext := decode_hex_for_test(t, "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")

  ciphertext, err := AESKeyWrap(kek, plaintext)
  if err != nil {
    t.Fatalf("AESKeyWrap failed: %v", err)
  }
  if !bytes.Equal(ciphertext, expected_ciphertext) {
    t.Errorf("wrap mismatch:\n  got:    %x\n  expect: %x", ciphertext, expected_ciphertext)
  }

  recovered_plaintext, err := AESKeyUnwrap(kek, ciphertext)
  if err != nil {
    t.Fatalf("AESKeyUnwrap failed: %v", err)
  }
  if !bytes.Equal(recovered_plaintext, plaintext) {
    t.Errorf("unwrap mismatch:\n  got:    %x\n  expect: %x", recovered_plaintext, plaintext)
  }
}

// RFC 3394 Section 4.5: Wrap 192 bits of Key Data with a 256-bit KEK.
//
// NOTE: The ciphertext published in the RFC for Section 4.5 corresponds to
// plaintext 001122...EEFF + 0001020304050607 (the first 24 bytes of the
// Section 4.6 plaintext), not the stated 001122...EEFF + 0011223344556677.
// The expected value below is independently verified by Python's
// cryptography.hazmat.primitives.keywrap.aes_key_wrap with the stated
// plaintext.
func TestAESKeyWrap_RFC3394_Vector_4_5_Wrap_192bit_Key_With_256bit_KEK(t *testing.T) {
  kek := decode_hex_for_test(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
  plaintext := decode_hex_for_test(t, "00112233445566778899AABBCCDDEEFF0011223344556677")
  expected_ciphertext := decode_hex_for_test(t, "3E7AEF8A04F35EBEB26440C8E4660D723F5BFC7AC4C017D627CD5E7C1A040339")

  ciphertext, err := AESKeyWrap(kek, plaintext)
  if err != nil {
    t.Fatalf("AESKeyWrap failed: %v", err)
  }
  if !bytes.Equal(ciphertext, expected_ciphertext) {
    t.Errorf("wrap mismatch:\n  got:    %x\n  expect: %x", ciphertext, expected_ciphertext)
  }

  recovered_plaintext, err := AESKeyUnwrap(kek, ciphertext)
  if err != nil {
    t.Fatalf("AESKeyUnwrap failed: %v", err)
  }
  if !bytes.Equal(recovered_plaintext, plaintext) {
    t.Errorf("unwrap mismatch:\n  got:    %x\n  expect: %x", recovered_plaintext, plaintext)
  }
}

// RFC 3394 Section 4.6: Wrap 256 bits of Key Data with a 256-bit KEK
func TestAESKeyWrap_RFC3394_Vector_4_6_Wrap_256bit_Key_With_256bit_KEK(t *testing.T) {
  kek := decode_hex_for_test(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
  plaintext := decode_hex_for_test(t, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
  expected_ciphertext := decode_hex_for_test(t, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")

  ciphertext, err := AESKeyWrap(kek, plaintext)
  if err != nil {
    t.Fatalf("AESKeyWrap failed: %v", err)
  }
  if !bytes.Equal(ciphertext, expected_ciphertext) {
    t.Errorf("wrap mismatch:\n  got:    %x\n  expect: %x", ciphertext, expected_ciphertext)
  }

  recovered_plaintext, err := AESKeyUnwrap(kek, ciphertext)
  if err != nil {
    t.Fatalf("AESKeyUnwrap failed: %v", err)
  }
  if !bytes.Equal(recovered_plaintext, plaintext) {
    t.Errorf("unwrap mismatch:\n  got:    %x\n  expect: %x", recovered_plaintext, plaintext)
  }
}

func TestAESKeyUnwrap_Rejects_Wrong_KEK(t *testing.T) {
  correct_kek := decode_hex_for_test(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
  wrong_kek := decode_hex_for_test(t, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
  plaintext := decode_hex_for_test(t, "00112233445566778899AABBCCDDEEFF")

  ciphertext, err := AESKeyWrap(correct_kek, plaintext)
  if err != nil {
    t.Fatalf("AESKeyWrap failed: %v", err)
  }

  _, err = AESKeyUnwrap(wrong_kek, ciphertext)
  if err == nil {
    t.Error("AESKeyUnwrap should have failed with wrong KEK, but succeeded")
  }
}

func TestAESKeyUnwrap_Rejects_Corrupted_Ciphertext(t *testing.T) {
  kek := decode_hex_for_test(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
  plaintext := decode_hex_for_test(t, "00112233445566778899AABBCCDDEEFF")

  ciphertext, err := AESKeyWrap(kek, plaintext)
  if err != nil {
    t.Fatalf("AESKeyWrap failed: %v", err)
  }

  corrupted_ciphertext := make([]byte, len(ciphertext))
  copy(corrupted_ciphertext, ciphertext)
  corrupted_ciphertext[12] ^= 0xFF

  _, err = AESKeyUnwrap(kek, corrupted_ciphertext)
  if err == nil {
    t.Error("AESKeyUnwrap should have failed with corrupted ciphertext, but succeeded")
  }
}

func TestAESKeyWrap_Rejects_Short_Plaintext(t *testing.T) {
  kek := make([]byte, 32)
  short_plaintext := make([]byte, 8)

  _, err := AESKeyWrap(kek, short_plaintext)
  if err == nil {
    t.Error("AESKeyWrap should reject plaintext shorter than 16 bytes")
  }
}

func TestAESKeyWrap_Rejects_Non_Multiple_Of_8(t *testing.T) {
  kek := make([]byte, 32)
  odd_plaintext := make([]byte, 17)

  _, err := AESKeyWrap(kek, odd_plaintext)
  if err == nil {
    t.Error("AESKeyWrap should reject plaintext that is not a multiple of 8 bytes")
  }
}

// Also verify RFC 3394 Section 4.1: 128-bit KEK (proves algorithm is
// correct for all AES key sizes, not just 256-bit).
func TestAESKeyWrap_RFC3394_Vector_4_1_Wrap_128bit_Key_With_128bit_KEK(t *testing.T) {
  kek := decode_hex_for_test(t, "000102030405060708090A0B0C0D0E0F")
  plaintext := decode_hex_for_test(t, "00112233445566778899AABBCCDDEEFF")
  expected_ciphertext := decode_hex_for_test(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

  ciphertext, err := AESKeyWrap(kek, plaintext)
  if err != nil {
    t.Fatalf("AESKeyWrap failed: %v", err)
  }
  if !bytes.Equal(ciphertext, expected_ciphertext) {
    t.Errorf("wrap mismatch:\n  got:    %x\n  expect: %x", ciphertext, expected_ciphertext)
  }

  recovered_plaintext, err := AESKeyUnwrap(kek, ciphertext)
  if err != nil {
    t.Fatalf("AESKeyUnwrap failed: %v", err)
  }
  if !bytes.Equal(recovered_plaintext, plaintext) {
    t.Errorf("unwrap mismatch:\n  got:    %x\n  expect: %x", recovered_plaintext, plaintext)
  }
}
