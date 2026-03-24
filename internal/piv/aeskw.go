// AES Key Wrap (RFC 3394) implementation.
//
// AES-KW wraps key material in 64-bit (8-byte) blocks using AES-ECB as the
// underlying cipher. The wrapped output is 8 bytes longer than the input
// (a 64-bit integrity check value is prepended).
//
// Constraints:
//   - Plaintext must be >= 16 bytes and a multiple of 8
//   - KEK must be a valid AES key (16, 24, or 32 bytes)
//
// Reference: https://www.rfc-editor.org/rfc/rfc3394

package piv

import (
  "crypto/aes"
  "encoding/binary"
  "errors"
  "fmt"
)

var aes_kw_default_integrity_check_value = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aes_key_wrap encrypts key material using AES Key Wrap (RFC 3394).
//
// kek: AES key encryption key (16, 24, or 32 bytes).
// plaintext: key data to wrap (>= 16 bytes, multiple of 8).
//
// Returns ciphertext that is 8 bytes longer than the input.
func AESKeyWrap(kek []byte, plaintext []byte) ([]byte, error) {
  if len(plaintext) < 16 {
    return nil, fmt.Errorf("plaintext must be at least 16 bytes for AES Key Wrap (got %d)", len(plaintext))
  }
  if len(plaintext)%8 != 0 {
    return nil, fmt.Errorf("plaintext must be a multiple of 8 bytes for AES Key Wrap (got %d)", len(plaintext))
  }

  block_cipher, err := aes.NewCipher(kek)
  if err != nil {
    return nil, fmt.Errorf("could not create AES cipher for key wrap: %w", err)
  }

  number_of_64bit_blocks := len(plaintext) / 8

  var integrity_register [8]byte
  copy(integrity_register[:], aes_kw_default_integrity_check_value[:])

  data_registers := make([][]byte, number_of_64bit_blocks)
  for block_index := 0; block_index < number_of_64bit_blocks; block_index++ {
    data_registers[block_index] = make([]byte, 8)
    copy(data_registers[block_index], plaintext[block_index*8:(block_index+1)*8])
  }

  for round := 0; round < 6; round++ {
    for block_index := 0; block_index < number_of_64bit_blocks; block_index++ {
      var aes_input_block [aes.BlockSize]byte
      copy(aes_input_block[:8], integrity_register[:])
      copy(aes_input_block[8:], data_registers[block_index])

      block_cipher.Encrypt(aes_input_block[:], aes_input_block[:])

      step_counter := uint64(number_of_64bit_blocks*round + block_index + 1)
      integrity_value := binary.BigEndian.Uint64(aes_input_block[:8])
      integrity_value ^= step_counter
      binary.BigEndian.PutUint64(integrity_register[:], integrity_value)

      copy(data_registers[block_index], aes_input_block[8:])
    }
  }

  wrapped_output := make([]byte, 0, (number_of_64bit_blocks+1)*8)
  wrapped_output = append(wrapped_output, integrity_register[:]...)
  for block_index := 0; block_index < number_of_64bit_blocks; block_index++ {
    wrapped_output = append(wrapped_output, data_registers[block_index]...)
  }

  return wrapped_output, nil
}

// aes_key_unwrap decrypts AES Key Wrap (RFC 3394) ciphertext.
//
// kek: the same AES key used during wrapping.
// ciphertext: the wrapped output from aes_key_wrap (>= 24 bytes, multiple of 8).
//
// Returns the original plaintext, or an error if the integrity check fails
// (indicating wrong KEK or corrupted data).
func AESKeyUnwrap(kek []byte, ciphertext []byte) ([]byte, error) {
  if len(ciphertext) < 24 {
    return nil, fmt.Errorf("ciphertext must be at least 24 bytes for AES Key Unwrap (got %d)", len(ciphertext))
  }
  if len(ciphertext)%8 != 0 {
    return nil, fmt.Errorf("ciphertext must be a multiple of 8 bytes for AES Key Unwrap (got %d)", len(ciphertext))
  }

  block_cipher, err := aes.NewCipher(kek)
  if err != nil {
    return nil, fmt.Errorf("could not create AES cipher for key unwrap: %w", err)
  }

  number_of_64bit_blocks := len(ciphertext)/8 - 1

  var integrity_register [8]byte
  copy(integrity_register[:], ciphertext[:8])

  data_registers := make([][]byte, number_of_64bit_blocks)
  for block_index := 0; block_index < number_of_64bit_blocks; block_index++ {
    data_registers[block_index] = make([]byte, 8)
    copy(data_registers[block_index], ciphertext[(block_index+1)*8:(block_index+2)*8])
  }

  for round := 5; round >= 0; round-- {
    for block_index := number_of_64bit_blocks - 1; block_index >= 0; block_index-- {
      step_counter := uint64(number_of_64bit_blocks*round + block_index + 1)
      integrity_value := binary.BigEndian.Uint64(integrity_register[:])
      integrity_value ^= step_counter
      binary.BigEndian.PutUint64(integrity_register[:], integrity_value)

      var aes_input_block [aes.BlockSize]byte
      copy(aes_input_block[:8], integrity_register[:])
      copy(aes_input_block[8:], data_registers[block_index])

      block_cipher.Decrypt(aes_input_block[:], aes_input_block[:])

      copy(integrity_register[:], aes_input_block[:8])
      copy(data_registers[block_index], aes_input_block[8:])
    }
  }

  if integrity_register != aes_kw_default_integrity_check_value {
    return nil, errors.New("AES Key Unwrap integrity check failed (wrong KEK or corrupted ciphertext)")
  }

  unwrapped_output := make([]byte, 0, number_of_64bit_blocks*8)
  for block_index := 0; block_index < number_of_64bit_blocks; block_index++ {
    unwrapped_output = append(unwrapped_output, data_registers[block_index]...)
  }

  return unwrapped_output, nil
}
