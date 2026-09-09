package aicjson

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

func TestMapX509ToClaimsErrorPaths(t *testing.T) {
	env := newTestEnv(t)

	t.Run("nil aic", func(t *testing.T) {
		_, _, err := MapX509ToClaims(nil, X509BridgeOptions{})
		requireErrContains(t, err, "nil AIC")
	})

	t.Run("principal realm empty", func(t *testing.T) {
		base := defaultXAIC(pki.DelegationAuthorized)
		base.PrincipalUid.Realm = ""
		_, _, err := MapX509ToClaims(base, X509BridgeOptions{})
		requireErrContains(t, err, "principalUid realm and identifier are required")
	})

	t.Run("principal keyhash empty", func(t *testing.T) {
		base := defaultXAIC(pki.DelegationAuthorized)
		base.PrincipalUid.KeyHash = nil
		_, _, err := MapX509ToClaims(base, X509BridgeOptions{})
		requireErrContains(t, err, "keyHash is required")
	})

	t.Run("principal unsupported hash algo", func(t *testing.T) {
		base := defaultXAIC(pki.DelegationAuthorized)
		base.PrincipalUid.HashAlgo = pki.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}
		_, _, err := MapX509ToClaims(base, X509BridgeOptions{})
		requireErrContains(t, err, "unsupported principalUid hash algo")
	})

	t.Run("invalid delegation mode", func(t *testing.T) {
		base := defaultXAIC(pki.DelegationAuthorized)
		base.DelegationMode = pki.DelegationMode(99)
		_, _, err := MapX509ToClaims(base, X509BridgeOptions{})
		requireErrContains(t, err, "invalid delegation mode")
	})

	t.Run("missing delegation authorization", func(t *testing.T) {
		base := defaultXAIC(pki.DelegationAuthorized)
		base.DelegationAuthorization = pki.DelegationAuthorization{}
		_, _, err := MapX509ToClaims(base, X509BridgeOptions{})
		requireErrContains(t, err, "delegationAuthorization is required")
	})

	t.Run("requested lifetime below 1", func(t *testing.T) {
		base := defaultXAIC(pki.DelegationAuthorized)
		base.DelegationAuthorization.RequestedLifetime = 0
		_, _, err := MapX509ToClaims(base, X509BridgeOptions{})
		requireErrContains(t, err, "requested_lifetime must be >= 1")
	})

	t.Run("options override now and lifetime", func(t *testing.T) {
		base := defaultXAIC(pki.DelegationAuthorized)
		base.DelegationAuthorization.RequestedLifetime = 10
		outer, da, err := MapX509ToClaims(base, X509BridgeOptions{
			Now:                 env.now,
			DARequestedLifetime: 99,
			DAAudience:          env.issuer.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if da.RequestedLifetime != 99 {
			t.Fatalf("lifetime %d != 99", da.RequestedLifetime)
		}
		if da.TS != env.now.Unix() {
			t.Fatalf("ts %d != env.now %d", da.TS, env.now.Unix())
		}
		if da.Exp != env.now.Unix()+99 {
			t.Fatalf("exp %d", da.Exp)
		}
		if outer.Aic.Extensions != nil {
			t.Fatalf("expected nil extensions for empty list")
		}
	})

	t.Run("mapDelegationMode variant", func(t *testing.T) {
		m, err := mapDelegationMode(pki.DelegationRepresentative)
		if err != nil || m != ModeRepresentative {
			t.Fatalf("mode=%q err=%v", m, err)
		}
		_, err = mapDelegationMode(pki.DelegationMode(7))
		requireErrContains(t, err, "invalid delegation mode")
	})

	t.Run("extensions preserved as base64url", func(t *testing.T) {
		base := defaultXAIC(pki.DelegationAuthorized)
		base.Extensions = []pki.ExtField{
			{ExtnID: asn1.ObjectIdentifier{1, 2, 3}, Critical: true, ExtnValue: []byte{1, 2, 3}},
		}
		outer, _, err := MapX509ToClaims(base, X509BridgeOptions{Now: env.now, DAAudience: env.issuer.ID})
		if err != nil {
			t.Fatal(err)
		}
		ext, ok := outer.Aic.Extensions["1.2.3"]
		if !ok {
			t.Fatalf("extension 1.2.3 missing: %v", outer.Aic.Extensions)
		}
		if !ext.Critical {
			t.Fatal("critical flag lost")
		}
		want := `{"der":"` + b64uEncode([]byte{1, 2, 3}) + `"}`
		if string(ext.Value) != want {
			t.Fatalf("ext value %q != %q", ext.Value, want)
		}
	})
}

func TestASN1HashNameVariants(t *testing.T) {
	cases := []struct {
		oid  asn1.ObjectIdentifier
		want string
	}{
		{pki.OIDSHA256, "sha-256"},
		{pki.OIDSHA384, "sha-384"},
		{pki.OIDSHA512, "sha-512"},
		{asn1.ObjectIdentifier{1, 2, 3}, ""},
	}
	for _, tc := range cases {
		if got := asn1HashName(tc.oid); got != tc.want {
			t.Fatalf("asn1HashName(%v) = %q, want %q", tc.oid, got, tc.want)
		}
	}
	if got := asn1HashName(pki.PrincipalUid{HashAlgo: pki.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{9, 9}}}.HashAlgoOID()); got != "" {
		t.Fatalf("unknown OID should map to empty name, got %q", got)
	}
}

func TestVerifyX509DelegationErrorPaths(t *testing.T) {
	env := newTestEnv(t)

	t.Run("nil aic", func(t *testing.T) {
		err := VerifyX509Delegation(nil, &env.principalKey.PublicKey, nil)
		requireErrContains(t, err, "nil AIC")
	})

	t.Run("missing delegation authorization", func(t *testing.T) {
		aic := defaultXAIC(pki.DelegationAuthorized)
		aic.DelegationAuthorization = pki.DelegationAuthorization{}
		err := VerifyX509Delegation(aic, &env.principalKey.PublicKey, nil)
		requireErrContains(t, err, "delegationAuthorization is required")
	})

	t.Run("ecdsa bad signature length", func(t *testing.T) {
		err := verifyDASignature(pki.OIDSigECDSAWithSHA256, []byte{1}, []byte{1, 2, 3}, &env.principalKey.PublicKey)
		requireErrContains(t, err, "signature length")
	})

	t.Run("ecdsa key type mismatch", func(t *testing.T) {
		err := verifyDASignature(pki.OIDSigECDSAWithSHA256, []byte{1}, make([]byte, 64), rsaPub(t))
		requireErrContains(t, err, "requires *ecdsa.PublicKey")
	})

	t.Run("rsa key type mismatch", func(t *testing.T) {
		err := verifyDASignature(pki.OIDSigRSAWithSHA256, []byte{1}, []byte{1}, &env.principalKey.PublicKey)
		requireErrContains(t, err, "requires *rsa.PublicKey")
	})

	t.Run("ed25519 key type mismatch", func(t *testing.T) {
		err := verifyDASignature(pki.OIDSigEd25519, []byte{1}, []byte{1}, &env.principalKey.PublicKey)
		requireErrContains(t, err, "requires ed25519.PublicKey")
	})

	t.Run("unsupported signature alg", func(t *testing.T) {
		err := verifyDASignature(asn1.ObjectIdentifier{9, 9, 9}, []byte{1}, []byte{1}, &env.principalKey.PublicKey)
		requireErrContains(t, err, "unsupported DelegationAuthorization signature algorithm")
	})
}

func TestVerifyDASignatureValidPaths(t *testing.T) {
	tbs := []byte("delegation tbs payload")

	t.Run("ecdsa sha256 genuine", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		digest := sha256.Sum256(tbs)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		sig := make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
		if err := verifyDASignature(pki.OIDSigECDSAWithSHA256, tbs, sig, &key.PublicKey); err != nil {
			t.Fatalf("ecdsa verify: %v", err)
		}
		err = verifyDASignature(pki.OIDSigECDSAWithSHA256, []byte("other"), sig, &key.PublicKey)
		requireErrContains(t, err, "signature invalid")
	})

	t.Run("rsa sha256 genuine", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		digest := sha256.Sum256(tbs)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyDASignature(pki.OIDSigRSAWithSHA256, tbs, sig, &key.PublicKey); err != nil {
			t.Fatalf("rsa verify: %v", err)
		}
		err = verifyDASignature(pki.OIDSigRSAWithSHA256, []byte("other"), sig, &key.PublicKey)
		requireErrContains(t, err, "signature invalid")
	})

	t.Run("ed25519 genuine", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(priv, tbs)
		if err := verifyDASignature(pki.OIDSigEd25519, tbs, sig, pub); err != nil {
			t.Fatalf("ed25519 verify: %v", err)
		}
		err = verifyDASignature(pki.OIDSigEd25519, []byte("other"), sig, pub)
		requireErrContains(t, err, "signature invalid")
	})
}

func rsaPub(t *testing.T) *rsa.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey
}

func defaultXAIC(mode pki.DelegationMode) *pki.AIC {
	return &pki.AIC{
		Version:        1,
		AgentId:        "agent:db-analyst-01",
		PrincipalUid:   pki.PrincipalUid{Version: 1, Realm: "corp.com", Identifier: "zhangsan", KeyHash: make([]byte, 32), HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256}},
		Capabilities:   x509AgentCaps(),
		DelegationMode: mode,
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "DATA_ANALYSIS", Description: "analysis"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC().Truncate(time.Second),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{1},
		},
	}
}
