package aicjson

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	pki "github.com/varwof/types"
)

// X509BridgeOptions carries the deployment context needed to map an
// X.509 AIC extension onto AIC-JWT claims (draft Section 5.4).  The
// RFC 7523 claims that have no ASN.1 counterpart (iss/sub/aud/exp of
// the inner DA) are supplied here at conversion time; see the final
// row of the Section 5.4 mapping table.
type X509BridgeOptions struct {
	// Now anchors the DA timestamp expression.  When zero the
	// certificate's own DelegationAuthorization timestamp is preserved.
	// A non-zero value lets a Mode-B issuer re-anchor the issued DA.
	Now time.Time

	// DAAudience is the intended authorization server that will redeem
	// the DA grant (RFC 7523 aud).
	DAAudience string

	// DARequestedLifetime overrides the certificate's requested
	// lifetime when positive; a zero value keeps the value embedded in
	// the certificate's DelegationAuthorization.
	DARequestedLifetime int
}

// MapX509ToClaims maps an X.509 AIC extension onto the equivalent
// OuterClaims and DAClaims in the JSON profile, exactly following the
// Section 5.4 mapping table.  The ten AIC fields shared between
// DelegationAuthTBS and the DA JWT payload are copied verbatim; the
// RFC 7523 claims are taken from opts.  No signing is performed: the
// caller is responsible for signing the outer token (and, where the
// principal's private key is available at issuance, the inner DA JWT)
// as described in draft Section 10.6 / Mode B.
func MapX509ToClaims(aic *pki.AIC, opts X509BridgeOptions) (*OuterClaims, *DAClaims, error) {
	if aic == nil {
		return nil, nil, fmt.Errorf("x509 bridge: nil AIC")
	}

	principal, err := mapPrincipal(aic.PrincipalUid)
	if err != nil {
		return nil, nil, err
	}
	mode, err := mapDelegationMode(aic.DelegationMode)
	if err != nil {
		return nil, nil, err
	}
	caps, err := mapCapabilities(aic.Capabilities)
	if err != nil {
		return nil, nil, err
	}
	constraints, err := mapCapabilities(aic.AuthorizationConstraints)
	if err != nil {
		return nil, nil, err
	}
	extensions, err := mapExtensions(aic.Extensions)
	if err != nil {
		return nil, nil, err
	}

	da, err := mapDA(aic, principal, mode, caps, constraints, opts)
	if err != nil {
		return nil, nil, err
	}

	outer := &OuterClaims{
		Sub: aic.AgentId,
		Aic: &AICClaims{
			Ver:            aic.Version,
			Principal:      principal,
			DelegationMode: mode,
			Capabilities:   caps,
			Constraints:    constraints,
			Extensions:     extensions,
		},
	}
	return outer, da, nil
}

func mapPrincipal(pu pki.PrincipalUid) (Principal, error) {
	if pu.Realm == "" || pu.Identifier == "" {
		return Principal{}, fmt.Errorf("x509 bridge: principalUid realm and identifier are required")
	}
	if len(pu.KeyHash) == 0 {
		return Principal{}, fmt.Errorf("x509 bridge: principalUid keyHash is required")
	}
	name := asn1HashName(pu.HashAlgoOID())
	if name == "" {
		return Principal{}, fmt.Errorf("x509 bridge: unsupported principalUid hash algo %v", pu.HashAlgoOID())
	}
	return Principal{
		Realm:   pu.Realm,
		ID:      pu.Identifier,
		KeyHash: b64uEncode(pu.KeyHash),
		HashAlg: name,
	}, nil
}

func asn1HashName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(pki.OIDSHA256):
		return "sha-256"
	case oid.Equal(pki.OIDSHA384):
		return "sha-384"
	case oid.Equal(pki.OIDSHA512):
		return "sha-512"
	}
	return ""
}

func mapDelegationMode(m pki.DelegationMode) (string, error) {
	switch m {
	case pki.DelegationAuthorized:
		return ModeAuthorized, nil
	case pki.DelegationRepresentative:
		return ModeRepresentative, nil
	}
	return "", fmt.Errorf("x509 bridge: invalid delegation mode %d", m)
}

func mapCapabilities(in []pki.Capability) ([]Capability, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]Capability, 0, len(in))
	for _, c := range in {
		out = append(out, PKIToCap(c))
	}
	return out, nil
}

func mapDA(aic *pki.AIC, principal Principal, mode string,
	caps, constraints []Capability, opts X509BridgeOptions) (*DAClaims, error) {

	da := aic.DelegationAuthorization
	if !da.IsPresent() {
		return nil, fmt.Errorf("x509 bridge: AIC delegationAuthorization is required per spec")
	}

	ts := da.Timestamp
	requested := da.RequestedLifetime
	if !opts.Now.IsZero() {
		ts = opts.Now
	}
	if opts.DARequestedLifetime > 0 {
		requested = opts.DARequestedLifetime
	}
	if requested < 1 {
		return nil, fmt.Errorf("x509 bridge: DA requested_lifetime must be >= 1")
	}

	d := &DAClaims{
		Ver:               2,
		Aud:               Audience{opts.DAAudience},
		AgentID:           aic.AgentId,
		Principal:         principal,
		Reason:            Reason{Code: da.Reason.ReasonCode, Desc: da.Reason.Description},
		Capabilities:      caps,
		DelegationMode:    mode,
		Constraints:       constraints,
		RequestedLifetime: requested,
		TS:                ts.Unix(),
		Nonce:             b64uEncode(da.Nonce),
	}
	d.Exp = ts.Unix() + int64(requested)
	d.Iat = ts.Unix()
	d.Jti = d.Nonce
	d.Iss = d.Principal.SubjectID()
	switch mode {
	case ModeAuthorized:
		d.Sub = d.AgentID
	case ModeRepresentative:
		d.Sub = d.Principal.SubjectID()
	default:
		return nil, fmt.Errorf("x509 bridge: invalid delegation mode %q", mode)
	}
	return d, nil
}

func mapExtensions(in []pki.ExtField) (map[string]Extension, error) {
	if in == nil {
		return nil, nil
	}
	var exts map[string]Extension
	for _, e := range in {
		if exts == nil {
			exts = make(map[string]Extension)
		}
		// AIC extension values are ASN.1 DER; the JSON profile carries
		// them as opaque JSON values.  There is no canonical JSON form
		// for arbitrary DER, so they are preserved as base64url.
		exts[e.ExtnID.String()] = Extension{
			Critical: e.Critical,
			Value:    []byte(`{"der":"` + b64uEncode(e.ExtnValue) + `"}`),
		}
	}
	return exts, nil
}

// VerifyX509Delegation verifies the principal-signed DelegationAuthorization
// embedded in an AIC extension.  It reconstructs the exact
// DelegationAuthTBS DER (draft Section 5.4 row: DelegationAuthTBS maps to
// the DA JWT payload) from the certificate's AIC fields and verifies
// `da.SignatureValue` against the principal's public key using the
// signature algorithm OID recorded in the extension.  This closes the
// ASN.1->JSON faithfulness gap: the ten AIC fields carried in the
// converted DA claims are the ones actually signed by the principal.
//
// agentSPKI is the SPKI of the certificate carrying the AIC.  Version 2
// appends the agentKeyBinding over this SPKI and requires it non-empty.
//
// Version negotiation mirrors core/internal/ca: version 0 (unspecified)
// prefers version 2 when the agent SPKI is available, then falls back to
// version 1.  Version 1 additionally tolerates the legacy pre-v2 encoding
// that emitted an explicit Version INTEGER 0.
func VerifyX509Delegation(aic *pki.AIC, principalPub crypto.PublicKey, agentSPKI []byte) error {
	if aic == nil {
		return fmt.Errorf("x509 bridge: nil AIC")
	}
	da := aic.DelegationAuthorization
	if !da.IsPresent() {
		return fmt.Errorf("x509 bridge: AIC delegationAuthorization is required per spec")
	}

	switch aic.Version {
	case pki.DAVersion2:
		if len(agentSPKI) == 0 {
			return fmt.Errorf("x509 bridge: DA version 2 requires the agent SPKI (agentKeyBinding)")
		}
		return verifyX509DelegationTBS(aic, principalPub, agentSPKI, pki.DAVersion2)
	case 0:
		if len(agentSPKI) > 0 {
			if err := verifyX509DelegationTBS(aic, principalPub, agentSPKI, pki.DAVersion2); err == nil {
				return nil
			}
		}
		return verifyX509DelegationTBS(aic, principalPub, agentSPKI, pki.DAVersion1)
	case pki.DAVersion1:
		return verifyX509DelegationTBS(aic, principalPub, agentSPKI, pki.DAVersion1)
	default:
		return fmt.Errorf("x509 bridge: unsupported DA version %d (must be 0, 1, or 2)", aic.Version)
	}
}

func verifyX509DelegationTBS(aic *pki.AIC, principalPub crypto.PublicKey, agentSPKI []byte, version int) error {
	if version != pki.DAVersion2 {
		if err := verifyX509DelegationTBSAt(aic, principalPub, agentSPKI, pki.DAVersion1); err == nil {
			return nil
		}
		return verifyX509DelegationTBSAt(aic, principalPub, agentSPKI, 0)
	}
	return verifyX509DelegationTBSAt(aic, principalPub, agentSPKI, pki.DAVersion2)
}

func verifyX509DelegationTBSAt(aic *pki.AIC, principalPub crypto.PublicKey, agentSPKI []byte, version int) error {
	da := aic.DelegationAuthorization

	tbs := pki.DelegationAuthTBS{
		Version:                  version,
		AgentId:                  aic.AgentId,
		PrincipalUid:             aic.PrincipalUid,
		Reason:                   da.Reason,
		Capabilities:             aic.Capabilities,
		DelegationMode:           aic.DelegationMode,
		AuthorizationConstraints: aic.AuthorizationConstraints,
		RequestedLifetime:        da.RequestedLifetime,
		Timestamp:                da.Timestamp,
		Nonce:                    da.Nonce,
	}
	if version == pki.DAVersion2 {
		binding, err := pki.MakeAgentKeyBinding(nil, agentSPKI)
		if err != nil {
			return fmt.Errorf("x509 bridge: agent key binding: %w", err)
		}
		tbs.AgentKeyBinding = binding
	}
	der, err := asn1.Marshal(tbs)
	if err != nil {
		return fmt.Errorf("x509 bridge: marshal DelegationAuthTBS: %w", err)
	}

	return verifyDASignature(da.SignatureAlgorithm.Algorithm, der, da.SignatureValue, principalPub)
}

func verifyDASignature(algOID asn1.ObjectIdentifier, tbs, sig []byte, pub crypto.PublicKey) error {
	switch {
	case algOID.Equal(pki.OIDSigECDSAWithSHA256), algOID.Equal(pki.OIDSigECDSAWithSHA384),
		algOID.Equal(pki.OIDSigECDSAWithSHA512):
		ek, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("x509 bridge: ECDSA signature requires *ecdsa.PublicKey, got %T", pub)
		}
		size := (ek.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return fmt.Errorf("x509 bridge: ECDSA signature length %d != %d", len(sig), 2*size)
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		hash := func() []byte {
			switch {
			case algOID.Equal(pki.OIDSigECDSAWithSHA256):
				d := sha256.Sum256(tbs)
				return d[:]
			case algOID.Equal(pki.OIDSigECDSAWithSHA384):
				d := sha512.Sum384(tbs)
				return d[:]
			default:
				d := sha512.Sum512(tbs)
				return d[:]
			}
		}()
		if !ecdsa.Verify(ek, hash, r, s) {
			return fmt.Errorf("x509 bridge: DelegationAuthTBS signature invalid")
		}
		return nil

	case algOID.Equal(pki.OIDSigRSAWithSHA256), algOID.Equal(pki.OIDSigRSAWithSHA384),
		algOID.Equal(pki.OIDSigRSAWithSHA512):
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("x509 bridge: RSA signature requires *rsa.PublicKey, got %T", pub)
		}
		var digest []byte
		var h crypto.Hash
		switch {
		case algOID.Equal(pki.OIDSigRSAWithSHA256):
			d := sha256.Sum256(tbs)
			digest, h = d[:], crypto.SHA256
		case algOID.Equal(pki.OIDSigRSAWithSHA384):
			d := sha512.Sum384(tbs)
			digest, h = d[:], crypto.SHA384
		default:
			d := sha512.Sum512(tbs)
			digest, h = d[:], crypto.SHA512
		}
		if err := rsa.VerifyPKCS1v15(rk, h, digest, sig); err != nil {
			return fmt.Errorf("x509 bridge: DelegationAuthTBS signature invalid: %w", err)
		}
		return nil

	case algOID.Equal(pki.OIDSigEd25519):
		ek, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("x509 bridge: Ed25519 signature requires ed25519.PublicKey, got %T", pub)
		}
		if !ed25519.Verify(ek, tbs, sig) {
			return fmt.Errorf("x509 bridge: DelegationAuthTBS signature invalid")
		}
		return nil

	default:
		return fmt.Errorf("x509 bridge: unsupported DelegationAuthorization signature algorithm %v", algOID)
	}
}
