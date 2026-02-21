"""
End-to-end test of sovereign enrollment using session mode (single UAC prompt).

This script:
  1. Starts an elevated session (ONE UAC prompt)
  2. Sends "extract" command -> gets EK cert + AK data
  3. Posts to server /enroll/begin (MakeCredential)
  4. Sends "activate" command -> TPM decrypts challenge
  5. Posts to server /enroll/activate (verifies decrypted secret)
  6. Closes session

The user sees only ONE UAC prompt for the entire enrollment.
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

API_BASE = "https://1id.com"
BINARY = os.path.join(os.path.dirname(__file__), "oneid-enroll.exe")


def api_post(path, body):
  url = f"{API_BASE}{path}"
  data = json.dumps(body).encode("utf-8")
  req = urllib.request.Request(url, data=data, method="POST")
  req.add_header("Content-Type", "application/json")
  req.add_header("Accept", "application/json")
  try:
    with urllib.request.urlopen(req, timeout=30) as resp:
      return json.loads(resp.read())
  except urllib.error.HTTPError as e:
    raw = e.read()
    try:
      body = json.loads(raw)
      print(f"API ERROR (HTTP {e.code}): {json.dumps(body, indent=2)}")
    except Exception:
      print(f"API ERROR (HTTP {e.code}): {raw.decode('utf-8', errors='replace')[:2000]}")
    sys.exit(1)


class SessionConnection:
  """Manages a TCP socket connection to an elevated oneid-enroll session."""

  def __init__(self, binary_path, timeout=120):
    self.binary_path = binary_path
    self.timeout = timeout
    self.server_socket = None
    self.conn = None
    self.reader = None
    self.process = None

  def __enter__(self):
    self.start()
    return self

  def __exit__(self, *args):
    self.close()

  def start(self):
    import secrets
    session_token = secrets.token_hex(32)

    # Create TCP server on random port
    self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.server_socket.bind(("127.0.0.1", 0))
    self.server_socket.listen(1)
    self.server_socket.settimeout(self.timeout)
    _, port = self.server_socket.getsockname()
    pipe_address = f"127.0.0.1:{port}"

    print(f"  Session socket listening on {pipe_address}")

    # Spawn the binary with session + elevated + pipe + token
    cmd = [
      self.binary_path, "session", "--elevated",
      "--pipe", pipe_address,
      "--session-token", session_token,
    ]
    self.process = subprocess.Popen(
      cmd,
      stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
    )

    # Wait for the elevated child to connect
    print("  Waiting for elevated process to connect (UAC will appear)...")
    self.conn, _ = self.server_socket.accept()
    self.conn.settimeout(self.timeout)

    # SECURITY: Close the listener immediately -- only one connection accepted
    self.server_socket.close()
    self.server_socket = None

    self.reader = self.conn.makefile("r")

    # Send the auth command with the shared token
    auth_cmd = json.dumps({"command": "auth", "args": {"token": session_token}}) + "\n"
    self.conn.sendall(auth_cmd.encode("utf-8"))

    # Read the auth response
    auth_resp = self._read_response()
    if not auth_resp.get("ok"):
      raise RuntimeError(f"Session auth failed: {auth_resp.get('error')}")
    print("  Session authenticated!")

    # Read the "ready" message
    ready = self._read_response()
    if not ready.get("ok"):
      raise RuntimeError(f"Session failed to start: {ready.get('error')}")
    print("  Session connected and ready!")

  def send_command(self, command, args=None):
    cmd_obj = {"command": command}
    if args:
      cmd_obj["args"] = args
    cmd_json = json.dumps(cmd_obj) + "\n"
    self.conn.sendall(cmd_json.encode("utf-8"))
    return self._read_response()

  def _read_response(self):
    line = self.reader.readline().strip()
    if not line:
      raise RuntimeError("Session returned empty response")
    return json.loads(line)

  def close(self):
    try:
      self.conn.sendall(b'{"command":"quit"}\n')
    except Exception:
      pass
    for r in [self.reader, self.conn, self.server_socket]:
      try:
        r.close()
      except Exception:
        pass
    if self.process:
      try:
        self.process.terminate()
        self.process.wait(timeout=5)
      except Exception:
        pass


print("=== SOVEREIGN ENROLLMENT E2E TEST (SESSION MODE - SINGLE UAC) ===\n")

with SessionConnection(BINARY) as sess:
  # Step 1: Extract from TPM (no separate UAC -- already elevated)
  print("\nStep 1: Extracting EK cert + AK from TPM...")
  extract_resp = sess.send_command("extract")
  if not extract_resp.get("ok"):
    print(f"  EXTRACT FAILED: {extract_resp.get('error')}")
    sys.exit(1)
  extract = extract_resp["data"]
  print(f"  EK fingerprint: {extract['ek_fingerprint'][:16]}...")
  print(f"  EK issuer: {extract.get('issuer_cn', 'N/A')}")
  print(f"  AK handle: {extract['ak_handle']}")
  print(f"  AK TPM Name: {extract['ak_tpm_name'][:16]}...")

  # Step 2: Begin enrollment (server runs MakeCredential)
  print("\nStep 2: Posting to /enroll/begin (MakeCredential)...")
  begin_resp = api_post("/api/v1/enroll/begin", {
    "ek_certificate_pem": extract["ek_cert_pem"],
    "ek_public_key_pem": extract["ek_public_pem"],
    "ak_public_key_pem": extract["ak_public_pem"],
    "ak_tpmt_public_b64": extract["ak_tpmt_public_b64"],
    "operator_email": "tpm-e2e-session-test@1id.com",
  })
  begin_data = begin_resp["data"]
  print(f"  Session: {begin_data['enrollment_session_id']}")
  print(f"  Trust tier: {begin_data['trust_tier']}")
  print(f"  Credential blob length: {len(begin_data['credential_blob'])} b64 chars")
  print(f"  Encrypted secret length: {len(begin_data['encrypted_secret'])} b64 chars")

  # Step 3: Activate credential (no separate UAC -- same session!)
  print("\nStep 3: Running TPM2_ActivateCredential (NO additional UAC!)...")
  activate_resp = sess.send_command("activate", {
    "credential_blob": begin_data["credential_blob"],
    "encrypted_secret": begin_data["encrypted_secret"],
    "ak_handle": extract["ak_handle"],
  })
  if not activate_resp.get("ok"):
    print(f"  ACTIVATE FAILED: {activate_resp.get('error')}")
    sys.exit(1)
  decrypted = activate_resp["data"]["decrypted_credential"]
  print(f"  Decrypted credential: {decrypted[:20]}...")

  # Step 4: Complete enrollment
  print("\nStep 4: Completing enrollment via /enroll/activate...")
  complete_resp = api_post("/api/v1/enroll/activate", {
    "enrollment_session_id": begin_data["enrollment_session_id"],
    "decrypted_credential": decrypted,
  })
  identity = complete_resp["data"]["identity"]
  credentials = complete_resp["data"]["credentials"]

  print(f"\n{'='*50}")
  print(f"  ENROLLMENT SUCCESSFUL (SINGLE UAC!)")
  print(f"{'='*50}")
  print(f"  Identity ID:     {identity['internal_id']}")
  print(f"  Handle:          {identity['handle']}")
  print(f"  Trust tier:      {identity['trust_tier']}")
  print(f"  TPM manufacturer:{identity.get('tpm_manufacturer', 'N/A')}")
  print(f"  Client ID:       {credentials['client_id']}")
  print(f"  Client secret:   {credentials['client_secret'][:8]}...")
  print(f"{'='*50}")
