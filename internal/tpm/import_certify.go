// Import-and-certify: the enrollment co-residency proof that needs NO elevation.
//
// The Registrar generates a restricted ECC P-256 SIGNING key and wraps it for
// our certified Endorsement Key (TPM 2.0 duplication format, authPolicy that
// can never be satisfied, so it can never be duplicated out again). We
// TPM2_Import + TPM2_Load it under the EK, then have THAT key TPM2_Certify our
// AK over the Registrar's nonce. The Registrar verifies the signature with the
// key it generated itself: only the TPM holding the EK private key can have
// loaded it, and a restricted key signs only TPM-generated attestations, so the
// certified AK Name (with its fixedTPM/restricted attributes) and its
// endorsement-hierarchy qualified Name are TPM-attested. That is the property
// TPM2_ActivateCredential proves.
//
// oneid-enroll 2.0.0 had the AK certify the imported object instead. That
// proved nothing about the AK: its attributes were the enrollee's claim and
// every attested field was public, so software could forge it (external
// review 2026-09-25, rfc/072 finding 1). Registrars reject that form.
//
// Why not ActivateCredential: Windows command blocking refuses it to
// non-elevated processes, while Import, Load and Certify are allowed
// (verified on Windows 10 1809 and Windows 11 26200 with a limited token,
// 2026-09-24; rfc/070_publication_push/notes/g1b_windows_tbs_privilege_investigation.md).
// AI agents usually have no operator to answer a UAC prompt.
//
// Transient objects only: nothing is persisted, no NV writes, no EvictControl.
package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ImportAndCertifyResult is returned to the SDK, which forwards it to the Registrar.
type ImportAndCertifyResult struct {
	CertifyInfo      []byte // marshaled TPMS_ATTEST certifying the AK
	CertifySignature []byte // ECDSA P-256 SHA-256 signature r||s (32+32) by the imported Registrar key
	AKTPMTPublic     []byte // our AK public area (for diagnostics)
	LoadedObjectName []byte // Name of the imported object as computed by the TPM
}

func startEndorsementPolicySession(tpmTransport transport.TPM) (tpm2.Session, func() error, error) {
	session, closeSession, err := tpm2.PolicySession(tpmTransport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("could not start policy session: %w", err)
	}
	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
		PolicySession: session.Handle(),
	}.Execute(tpmTransport)
	if err != nil {
		closeSession()
		return nil, nil, fmt.Errorf("PolicySecret(endorsement) failed: %w", err)
	}
	return session, closeSession, nil
}

// ImportAndCertifyWrappedObjectUnderEndorsementKey performs the agent side of
// the proof. objectPublic is the marshaled TPMT_PUBLIC from the Registrar,
// duplicate the TPM2B_PRIVATE contents, inSymSeed the OAEP-wrapped seed.
func ImportAndCertifyWrappedObjectUnderEndorsementKey(
	tpmTransport transport.TPMCloser,
	objectPublic []byte,
	duplicate []byte,
	inSymSeed []byte,
	registrarNonce []byte,
) (*ImportAndCertifyResult, error) {
	ekResponse, err := createTransientEK(tpmTransport)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: ekResponse.ObjectHandle}.Execute(tpmTransport)

	akData, err := CreateTransientAK(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not re-create the transient AK: %w", err)
	}
	defer FlushTransientAK(tpmTransport, akData)
	akReadPublic, err := tpm2.ReadPublic{ObjectHandle: akData.TransientHandle}.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not read AK public area: %w", err)
	}

	wrappedObjectPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](objectPublic)

	importSession, closeImportSession, err := startEndorsementPolicySession(tpmTransport)
	if err != nil {
		return nil, err
	}
	imported, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{Handle: ekResponse.ObjectHandle, Name: ekResponse.Name, Auth: importSession},
		ObjectPublic: wrappedObjectPublic,
		Duplicate:    tpm2.TPM2BPrivate{Buffer: duplicate},
		InSymSeed:    tpm2.TPM2BEncryptedSecret{Buffer: inSymSeed},
		Symmetric:    tpm2.TPMTSymDef{Algorithm: tpm2.TPMAlgNull},
	}.Execute(tpmTransport)
	closeImportSession()
	if err != nil {
		return nil, fmt.Errorf("TPM2_Import under the EK failed (object not wrapped for this TPM?): %w", err)
	}

	loadSession, closeLoadSession, err := startEndorsementPolicySession(tpmTransport)
	if err != nil {
		return nil, err
	}
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: ekResponse.ObjectHandle, Name: ekResponse.Name, Auth: loadSession},
		InPrivate:    imported.OutPrivate,
		InPublic:     wrappedObjectPublic,
	}.Execute(tpmTransport)
	closeLoadSession()
	if err != nil {
		return nil, fmt.Errorf("TPM2_Load under the EK failed: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(tpmTransport)

	// The imported Registrar key certifies the AK (not the other way round).
	certified, err := tpm2.Certify{
		ObjectHandle:   tpm2.AuthHandle{Handle: akData.TransientHandle, Name: akReadPublic.Name, Auth: tpm2.PasswordAuth(nil)},
		SignHandle:     tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: registrarNonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Certify of the AK by the imported Registrar key failed: %w", err)
	}
	ecdsaSignature, err := certified.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("imported Registrar key signature is not ECDSA (is this a 2.1.0 challenge?): %w", err)
	}
	rawSignatureRS := append(leftPadTo32Bytes(ecdsaSignature.SignatureR.Buffer), leftPadTo32Bytes(ecdsaSignature.SignatureS.Buffer)...)

	return &ImportAndCertifyResult{
		CertifyInfo:      certified.CertifyInfo.Bytes(),
		CertifySignature: rawSignatureRS,
		AKTPMTPublic:     akData.TPMTPublicBytes,
		LoadedObjectName: loaded.Name.Buffer,
	}, nil
}

// leftPadTo32Bytes returns a P-256 scalar as exactly 32 big-endian octets.
func leftPadTo32Bytes(value []byte) []byte {
	if len(value) >= 32 {
		return value[len(value)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(value):], value)
	return padded
}
