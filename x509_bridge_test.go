package aicjson

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// buildAICCert constructs a real X.509 certificate whose OIDAIC
// extension contains a principal-signed DelegationAuthorization (the
// exact structure ParseAIC unpacks).  The DA signature is a genuine
// asn1.SignatureValue over DelegationAuthTBS using the principal's
// ECDSA P-256 key.
func buildAICCert(t *testing.T, env *testEnv, caps []pki.Capability, nonce []byte, ts time.Time) *x509.Certificate {
	t.Helper()

	realm, id := "corp.com", "zhangsan"
	uid, err := pki.MakePrincipalUidFromCertWithAlgo(realm, id, env.principalCert, pki.OIDSHA256)
	if err != nil {
		t.Fatal(err)
	}

	tbs := pki.DelegationAuthTBS{
		Version:           1,
		AgentId:           "agent:db-analyst-01",
		PrincipalUid:      uid,
		Reason:            pki.Reason{ReasonCode: "DATA_ANALYSIS", Description: "scheduled analysis"},
		Capabilities:      caps,
		DelegationMode:    pki.DelegationAuthorized,
		RequestedLifetime: 3600,
		Timestamp:         ts,
		Nonce:             nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	r, s, err := ecdsa.Sign(rand.Reader, env.principalKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	size := (env.principalKey.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])

	aic := pki.AIC{
		Version:        1,
		AgentId:        "agent:db-analyst-01",
		PrincipalUid:   uid,
		Capabilities:   caps,
		DelegationMode: pki.DelegationAuthorized,
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "DATA_ANALYSIS", Description: "scheduled analysis"},
			RequestedLifetime:  3600,
			Timestamp:          ts,
			Nonce:              nonce,
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     sig,
		},
	}
	extValue, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent:db-analyst-01"},
		NotBefore:    ts.Add(-time.Minute),
		NotAfter:     ts.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Value: extValue},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &env.agentKey.PublicKey, env.agentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func x509AgentCaps() []pki.Capability {
	return []pki.Capability{
		{SchemeId: "database", CapabilityId: "query:*"},
		{SchemeId: "http", CapabilityId: "GET:/api/v1/*"},
	}
}

func TestMapX509ToClaims(t *testing.T) {
	env := newTestEnv(t)
	for _, mode := range []struct {
		name     string
		dMode    pki.DelegationMode
		jsonMode string
	}{
		{"authorized", pki.DelegationAuthorized, ModeAuthorized},
		{"representative", pki.DelegationRepresentative, ModeRepresentative},
	} {
		t.Run(mode.name, func(t *testing.T) {
			nonce := make([]byte, 32)
			ts := time.Now().UTC().Truncate(time.Second)
			aic := &pki.AIC{
				Version:        1,
				AgentId:        "agent:db-analyst-01",
				PrincipalUid:   pki.MakePrincipalUidFromCert("corp.com", "zhangsan", env.principalCert),
				Capabilities:   x509AgentCaps(),
				DelegationMode: mode.dMode,
				DelegationAuthorization: pki.DelegationAuthorization{
					Reason:            pki.Reason{ReasonCode: "DATA_ANALYSIS", Description: "scheduled analysis"},
					RequestedLifetime: 3600,
					Timestamp:         ts,
					Nonce:             nonce,
				},
			}

			outer, da, err := MapX509ToClaims(aic, X509BridgeOptions{
				Now:        ts,
				DAAudience: env.issuer.ID,
			})
			if err != nil {
				t.Fatal(err)
			}

			if outer.Sub != "agent:db-analyst-01" {
				t.Fatalf("outer sub = %q", outer.Sub)
			}
			if da.AgentID != "agent:db-analyst-01" {
				t.Fatalf("DA agent_id = %q", da.AgentID)
			}
			if da.DelegationMode != mode.jsonMode || outer.Aic.DelegationMode != mode.jsonMode {
				t.Fatalf("mode mismatch: da=%q outer=%q", da.DelegationMode, outer.Aic.DelegationMode)
			}
			if len(da.Capabilities) != 2 {
				t.Fatalf("capability count %d != 2", len(da.Capabilities))
			}
			if da.Principal.SubjectID() != "corp.com:zhangsan" {
				t.Fatalf("principal subject %q", da.Principal.SubjectID())
			}
			spkiHash, _ := SPKIHash(env.principalCert, "sha-256")
			if da.Principal.KeyHash != spkiHash {
				t.Fatalf("key_hash %q != SPKI hash %q", da.Principal.KeyHash, spkiHash)
			}
			if da.Ver != 2 {
				t.Fatalf("DA ver %d", da.Ver)
			}
			if da.Nonce != b64uEncode(nonce) || da.Jti != da.Nonce {
				t.Fatalf("nonce/jti mismatch")
			}
			if da.Iss != "corp.com:zhangsan" {
				t.Fatalf("DA iss %q", da.Iss)
			}
			if da.Exp != ts.Unix()+3600 {
				t.Fatalf("exp %d != %d", da.Exp, ts.Unix()+3600)
			}
			if da.Iat != ts.Unix() {
				t.Fatalf("iat %d", da.Iat)
			}
			if len(da.Aud) != 1 || da.Aud[0] != env.issuer.ID {
				t.Fatalf("DA aud %v", da.Aud)
			}

			if mode.jsonMode == ModeAuthorized {
				if da.Sub != da.AgentID {
					t.Fatalf("authorized DA sub %q != agent %q", da.Sub, da.AgentID)
				}
			} else {
				if da.Sub != da.Principal.SubjectID() {
					t.Fatalf("representative DA sub %q != principal %q", da.Sub, da.Principal.SubjectID())
				}
			}
		})
	}
}

func TestVerifyX509Delegation(t *testing.T) {
	env := newTestEnv(t)
	nonce := make([]byte, 32)
	ts := time.Now().UTC().Truncate(time.Second)
	cert := buildAICCert(t, env, x509AgentCaps(), nonce, ts)

	aic, err := pki.ParseAIC(cert)
	if err != nil {
		t.Fatal(err)
	}
	if aic == nil || aic.AgentId != "agent:db-analyst-01" {
		t.Fatalf("ParseAIC returned %+v", aic)
	}

	// The embedded ASN.1 DA signature verifies over the reconstructed
	// DelegationAuthTBS (the ASN.1->JSON faithfulness proof).
	if err := VerifyX509Delegation(aic, &env.principalKey.PublicKey); err != nil {
		t.Fatalf("VerifyX509Delegation: %v", err)
	}

	// Rebuilding the TBS with a tampered agent id must break verification.
	badAIC := *aic
	badAIC.AgentId = "agent:attacker"
	if err := VerifyX509Delegation(&badAIC, &env.principalKey.PublicKey); err == nil {
		t.Fatal("expected signature mismatch for tampered agent_id")
	}

	// A wrong principal public key must fail.
	if err := VerifyX509Delegation(aic, &env.agentKey.PublicKey); err == nil {
		t.Fatal("expected failure with wrong principal key")
	}
}

func TestMapX509ToSignedDA(t *testing.T) {
	env := newTestEnv(t)
	nonce := make([]byte, 32)
	ts := time.Now().UTC().Truncate(time.Second)
	cert := buildAICCert(t, env, x509AgentCaps(), nonce, ts)
	aic, err := pki.ParseAIC(cert)
	if err != nil {
		t.Fatal(err)
	}

	_, da, err := MapX509ToClaims(aic, X509BridgeOptions{
		Now:        ts,
		DAAudience: env.issuer.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Bridge the mapped claims onto a principal-signed DA JWT (Mode B:
	// a server-side helper issues the equivalent AIC-JWT).
	pb, _ := json.Marshal(da)
	hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": TypDA, "kid": "principal-1"})
	daToken, err := SignCompact(hb, pb, "ES256", env.principalKey)
	if err != nil {
		t.Fatal(err)
	}

	// The converted DA must be a valid, principal-signed DA JWT.
	if _, err := ValidateDA(daToken, VerifyOptions{
		Now:           env.now,
		PrincipalJWKS: map[string]crypto.PublicKey{"principal-1": &env.principalKey.PublicKey},
	}); err != nil {
		t.Fatalf("ValidateDA on converted DA: %v", err)
	}

	// The converted DA drives the same authorized-mode resource decision
	// as a natively-issued AIC-JWT, end to end.
	tok, _, err := env.issuer.IssueFromDAShort(daToken, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, 600, env.now)
	if err != nil {
		t.Fatalf("IssueFromDAShort on converted DA: %v", err)
	}
	dec, err := env.rs.Check(HTTPRequest{
		Method:      "GET",
		URL:         "https://rs.example.com/api/db",
		Audience:    "https://rs.example.com",
		AuthzHeader: "Bearer " + tok,
		RequestCap:  &Capability{Scheme: "database", ID: "query:SELECT"},
		Context:     defaultCtx(env),
	}, env.now)
	if err != nil || !dec.Permit {
		t.Fatalf("RS decision on converted chain: err=%v permit=%v", err, dec)
	}
}
