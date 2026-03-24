import Foundation
import CryptoKit

let key_storage_directory_name = ".1id"
let key_storage_subdirectory_name = "enclave_keys"

func get_key_storage_directory() throws -> URL {
  let home_directory = FileManager.default.homeDirectoryForCurrentUser
  let storage_directory = home_directory
    .appendingPathComponent(key_storage_directory_name)
    .appendingPathComponent(key_storage_subdirectory_name)
  try FileManager.default.createDirectory(at: storage_directory, withIntermediateDirectories: true)
  return storage_directory
}

func get_key_file_path(application_tag: String) throws -> URL {
  let safe_filename = application_tag
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "..", with: "_")
  return try get_key_storage_directory().appendingPathComponent("\(safe_filename).key")
}

func output_json(_ dict: [String: Any]) {
  if let json_data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]),
     let json_string = String(data: json_data, encoding: .utf8) {
    print(json_string)
  }
}

func output_error(_ error_code: String, _ message: String) {
  output_json(["error": message, "error_code": error_code])
}

func output_success(_ payload: [String: Any]) {
  var result = payload
  result["status"] = "ok"
  output_json(result)
}

func command_detect() {
  if SecureEnclave.isAvailable {
    output_success([
      "has_secure_enclave": true,
      "platform": "darwin/\(get_architecture_string())"
    ])
  } else {
    output_success([
      "has_secure_enclave": false,
      "platform": "darwin/\(get_architecture_string())"
    ])
  }
}

func get_architecture_string() -> String {
  #if arch(arm64)
  return "arm64"
  #elseif arch(x86_64)
  return "x86_64"
  #else
  return "unknown"
  #endif
}

func export_public_key_as_pem(_ public_key: P256.Signing.PublicKey) -> String {
  let raw_representation = public_key.x963Representation
  let asn1_header: [UInt8] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
  ]
  let spki_der = Data(asn1_header) + raw_representation
  let encoding_options: Data.Base64EncodingOptions = [.lineLength64Characters, .endLineWithLineFeed]
  let base64_encoded = spki_der.base64EncodedString(options: encoding_options)
  return "-----BEGIN PUBLIC KEY-----\n\(base64_encoded)\n-----END PUBLIC KEY-----\n"
}

func command_generate(application_tag: String) {
  guard SecureEnclave.isAvailable else {
    output_error("SE_NOT_AVAILABLE", "Secure Enclave is not available on this Mac")
    return
  }

  do {
    let key_file_path = try get_key_file_path(application_tag: application_tag)
    var key_was_newly_generated = true

    let private_key: SecureEnclave.P256.Signing.PrivateKey

    if FileManager.default.fileExists(atPath: key_file_path.path) {
      let stored_key_data = try Data(contentsOf: key_file_path)
      private_key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored_key_data)
      key_was_newly_generated = false
    } else {
      private_key = try SecureEnclave.P256.Signing.PrivateKey()
      try private_key.dataRepresentation.write(to: key_file_path)
      try FileManager.default.setAttributes(
        [.posixPermissions: 0o600], ofItemAtPath: key_file_path.path)
    }

    let public_key_pem = export_public_key_as_pem(private_key.publicKey)

    output_success([
      "public_key_pem": public_key_pem,
      "key_tag": application_tag,
      "algorithm": "ecdsa-p256",
      "key_was_newly_generated": key_was_newly_generated
    ])
  } catch {
    output_error("SE_KEY_GENERATION_FAILED", "Secure Enclave key generation failed: \(error)")
  }
}

func command_sign(application_tag: String, nonce_base64: String) {
  guard SecureEnclave.isAvailable else {
    output_error("SE_NOT_AVAILABLE", "Secure Enclave is not available on this Mac")
    return
  }

  do {
    let key_file_path = try get_key_file_path(application_tag: application_tag)

    guard FileManager.default.fileExists(atPath: key_file_path.path) else {
      output_error("SE_KEY_NOT_FOUND",
        "No Enclave key found for tag '\(application_tag)'. Run extract --type enclave first.")
      return
    }

    guard let nonce_data = Data(base64Encoded: nonce_base64) else {
      output_error("INVALID_NONCE", "Could not decode nonce from base64")
      return
    }

    let stored_key_data = try Data(contentsOf: key_file_path)
    let private_key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored_key_data)

    let signature = try private_key.signature(for: nonce_data)

    let signature_der = signature.derRepresentation
    let signature_base64 = signature_der.base64EncodedString()
    let public_key_pem = export_public_key_as_pem(private_key.publicKey)

    output_success([
      "signature_b64": signature_base64,
      "algorithm": "ecdsa-p256-sha256",
      "key_tag": application_tag,
      "public_key_pem": public_key_pem
    ])
  } catch {
    output_error("SE_SIGN_FAILED", "Secure Enclave signing failed: \(error)")
  }
}

func command_test() {
  guard SecureEnclave.isAvailable else {
    output_error("SE_NOT_AVAILABLE", "Secure Enclave is not available on this Mac")
    return
  }

  do {
    let test_data = "1id.com Secure Enclave hardware verification test".data(using: .utf8)!

    let private_key = try SecureEnclave.P256.Signing.PrivateKey()
    let signature = try private_key.signature(for: test_data)

    let public_key_pem = export_public_key_as_pem(private_key.publicKey)
    let signature_base64 = signature.derRepresentation.base64EncodedString()
    let test_data_base64 = test_data.base64EncodedString()

    output_success([
      "public_key_pem": public_key_pem,
      "signature_b64": signature_base64,
      "algorithm": "ecdsa-p256-sha256",
      "test_data_b64": test_data_base64
    ])
  } catch {
    output_error("SE_TEST_FAILED", "Secure Enclave test failed: \(error)")
  }
}

func get_keywrap_key_file_path(application_tag: String) throws -> URL {
  let safe_filename = application_tag
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "..", with: "_")
  return try get_key_storage_directory().appendingPathComponent("\(safe_filename).keywrap.key")
}

func export_keywrap_public_key_as_pem(_ public_key: P256.KeyAgreement.PublicKey) -> String {
  let raw_representation = public_key.x963Representation
  let asn1_header: [UInt8] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
  ]
  let spki_der = Data(asn1_header) + raw_representation
  let encoding_options: Data.Base64EncodingOptions = [.lineLength64Characters, .endLineWithLineFeed]
  let base64_encoded = spki_der.base64EncodedString(options: encoding_options)
  return "-----BEGIN PUBLIC KEY-----\n\(base64_encoded)\n-----END PUBLIC KEY-----\n"
}

func load_or_create_keywrap_key(application_tag: String) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
  let key_file_path = try get_keywrap_key_file_path(application_tag: application_tag)

  if FileManager.default.fileExists(atPath: key_file_path.path) {
    let stored_key_data = try Data(contentsOf: key_file_path)
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: stored_key_data)
  }

  let private_key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
  try private_key.dataRepresentation.write(to: key_file_path)
  try FileManager.default.setAttributes(
    [.posixPermissions: 0o600], ofItemAtPath: key_file_path.path)
  return private_key
}

func command_keywrap_pubkey(application_tag: String) {
  guard SecureEnclave.isAvailable else {
    output_error("SE_NOT_AVAILABLE", "Secure Enclave is not available on this Mac")
    return
  }

  do {
    let private_key = try load_or_create_keywrap_key(application_tag: application_tag)
    let public_key_pem = export_keywrap_public_key_as_pem(private_key.publicKey)
    let x963_b64 = private_key.publicKey.x963Representation.base64EncodedString()

    output_success([
      "public_key_pem": public_key_pem,
      "public_key_x963_b64": x963_b64,
      "key_tag": application_tag,
      "algorithm": "ecdh-p256"
    ])
  } catch {
    output_error("SE_KEYWRAP_PUBKEY_FAILED", "Could not get keywrap public key: \(error)")
  }
}

func command_ecdh(application_tag: String, peer_public_key_x963_base64: String) {
  guard SecureEnclave.isAvailable else {
    output_error("SE_NOT_AVAILABLE", "Secure Enclave is not available on this Mac")
    return
  }

  do {
    let private_key = try load_or_create_keywrap_key(application_tag: application_tag)

    guard let peer_pub_data = Data(base64Encoded: peer_public_key_x963_base64) else {
      output_error("INVALID_PEER_KEY", "Could not decode peer public key from base64")
      return
    }

    let peer_public_key = try P256.KeyAgreement.PublicKey(x963Representation: peer_pub_data)
    let shared_secret = try private_key.sharedSecretFromKeyAgreement(with: peer_public_key)

    let shared_secret_data: Data = shared_secret.withUnsafeBytes { ptr in
      Data(ptr)
    }

    output_success([
      "shared_secret_b64": shared_secret_data.base64EncodedString(),
      "key_tag": application_tag,
      "algorithm": "ecdh-p256"
    ])
  } catch {
    output_error("SE_ECDH_FAILED", "Secure Enclave ECDH failed: \(error)")
  }
}

func print_usage() {
  let usage = """
  oneid-se-helper: Secure Enclave operations for 1id.com

  Usage:
    oneid-se-helper detect
    oneid-se-helper generate --tag <application_tag>
    oneid-se-helper sign --tag <application_tag> --nonce <base64>
    oneid-se-helper keywrap-pubkey --tag <application_tag>
    oneid-se-helper ecdh --tag <application_tag> --peer-pub <base64>
    oneid-se-helper test

  All output is JSON on stdout.
  """
  fputs(usage, stderr)
}

let arguments = CommandLine.arguments
guard arguments.count >= 2 else {
  print_usage()
  exit(1)
}

let command = arguments[1]

switch command {
case "detect":
  command_detect()

case "generate":
  guard let tag_index = arguments.firstIndex(of: "--tag"),
        tag_index + 1 < arguments.count else {
    output_error("MISSING_TAG", "generate requires --tag <application_tag>")
    exit(1)
  }
  command_generate(application_tag: arguments[tag_index + 1])

case "sign":
  guard let tag_index = arguments.firstIndex(of: "--tag"),
        tag_index + 1 < arguments.count else {
    output_error("MISSING_TAG", "sign requires --tag <application_tag>")
    exit(1)
  }
  guard let nonce_index = arguments.firstIndex(of: "--nonce"),
        nonce_index + 1 < arguments.count else {
    output_error("MISSING_NONCE", "sign requires --nonce <base64>")
    exit(1)
  }
  command_sign(application_tag: arguments[tag_index + 1], nonce_base64: arguments[nonce_index + 1])

case "keywrap-pubkey":
  guard let tag_index = arguments.firstIndex(of: "--tag"),
        tag_index + 1 < arguments.count else {
    output_error("MISSING_TAG", "keywrap-pubkey requires --tag <application_tag>")
    exit(1)
  }
  command_keywrap_pubkey(application_tag: arguments[tag_index + 1])

case "ecdh":
  guard let tag_index = arguments.firstIndex(of: "--tag"),
        tag_index + 1 < arguments.count else {
    output_error("MISSING_TAG", "ecdh requires --tag <application_tag>")
    exit(1)
  }
  guard let peer_pub_index = arguments.firstIndex(of: "--peer-pub"),
        peer_pub_index + 1 < arguments.count else {
    output_error("MISSING_PEER_PUB", "ecdh requires --peer-pub <base64>")
    exit(1)
  }
  command_ecdh(
    application_tag: arguments[tag_index + 1],
    peer_public_key_x963_base64: arguments[peer_pub_index + 1])

case "test":
  command_test()

default:
  print_usage()
  exit(1)
}

