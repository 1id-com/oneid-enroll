# Quick test: extract EK + AK from the TPM (requires admin)
# Run from an elevated PowerShell prompt.

$binary = ".\oneid-enroll.exe"
$output = & $binary extract --json 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED (exit code $LASTEXITCODE):" -ForegroundColor Red
    Write-Host $output
    exit 1
}

$data = $output | ConvertFrom-Json

Write-Host "`nExtract succeeded!" -ForegroundColor Green
Write-Host "  EK Subject: $($data.subject_cn)"
Write-Host "  EK Issuer:  $($data.issuer_cn)"
Write-Host "  EK Fingerprint: $($data.ek_fingerprint.Substring(0, 16))..."
Write-Host "  AK Handle:  $($data.ak_handle)"
Write-Host "  AK TPM Name: $($data.ak_tpm_name.Substring(0, 16))..."
Write-Host "  AK TPMT_Public (base64, first 40 chars): $($data.ak_tpmt_public_b64.Substring(0, 40))..."

# Save to a file for the next step
$output | Set-Content "extract_result.json"
Write-Host "`nSaved to extract_result.json for next step."
