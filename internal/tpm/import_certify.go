// Import-and-certify: the enrollment co-residency proof that needs NO elevation.
//
// The Registrar wraps a small data object for our certified Endorsement Key
// (TPM 2.0 duplication format). We TPM2_Import + TPM2_Load it under the EK,
// then TPM2_Certify it with our AK over the Registrar's nonce. Only the TPM
// holding the EK private key can load the object, and a restricted AK only
// signs TPM-generated attestations, so this proves the AK lives in the
// certified TPM -- the same property TPM2_ActivateCredential proved.
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
	CertifyInfo      []byte // marshaled TPMS_ATTEST
	CertifySignature []byte // RSASSA-PKCS1-v1_5 SHA-256 signature by the AK
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

	certified, err := tpm2.Certify{
		ObjectHandle:   tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: tpm2.PasswordAuth(nil)},
		SignHandle:     tpm2.AuthHandle{Handle: akData.TransientHandle, Name: akReadPublic.Name, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: registrarNonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Certify by the AK failed: %w", err)
	}
	rsaSignature, err := certified.Signature.Signature.RSASSA()
	if err != nil {
		return nil, fmt.Errorf("AK signature is not RSASSA: %w", err)
	}

	return &ImportAndCertifyResult{
		CertifyInfo:      certified.CertifyInfo.Bytes(),
		CertifySignature: rsaSignature.Sig.Buffer,
		AKTPMTPublic:     akData.TPMTPublicBytes,
		LoadedObjectName: loaded.Name.Buffer,
	}, nil
}
