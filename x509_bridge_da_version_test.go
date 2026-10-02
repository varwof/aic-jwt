package aicjson

import (
	"encoding/asn1"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// TestBridgeDAVersionMapping covers the Section 5.4 mapping of the DA
// version across carriers: X.509 DA v1 maps to da.ver=2 (legacy, no
// binding) and X.509 DA v2 maps to da.ver=3 with an agent_key_binding.
func TestBridgeDAVersionMapping(t *testing.T) {
	opts := func() X509BridgeOptions {
		return X509BridgeOptions{
			Now:        time.Now().UTC().Truncate(time.Second),
			DAAudience: "https://as.example.com",
		}
	}

	t.Run("default_keeps_the_legacy_v1_mapping", func(t *testing.T) {
		_, da, err := MapX509ToClaims(defaultXAIC(pki.DelegationAuthorized), opts())
		if err != nil {
			t.Fatal(err)
		}
		if da.Ver != 2 {
			t.Fatalf("X.509 DA v1 (default) must map to da.ver=2, got %d", da.Ver)
		}
		if da.AgentKeyBinding != nil {
			t.Fatalf("da.ver=2 must not carry agent_key_binding")
		}
	})

	t.Run("v1_explicit_maps_to_ver2", func(t *testing.T) {
		o := opts()
		o.DAVersion = pki.DAVersion1
		_, da, err := MapX509ToClaims(defaultXAIC(pki.DelegationAuthorized), o)
		if err != nil {
			t.Fatal(err)
		}
		if da.Ver != 2 || da.AgentKeyBinding != nil {
			t.Fatalf("DA v1 must map to ver=2 without a binding, got ver=%d binding=%v", da.Ver, da.AgentKeyBinding)
		}
	})

	t.Run("v2_maps_to_ver3_with_binding", func(t *testing.T) {
		o := opts()
		o.DAVersion = pki.DAVersion2
		keyHash := make([]byte, 32)
		for i := range keyHash {
			keyHash[i] = byte(i)
		}
		o.AgentKeyBinding = &pki.AgentKeyBinding{KeyHash: keyHash} // hashAlgo omitted -> SHA-256
		_, da, err := MapX509ToClaims(defaultXAIC(pki.DelegationAuthorized), o)
		if err != nil {
			t.Fatal(err)
		}
		if da.Ver != 3 {
			t.Fatalf("X.509 DA v2 must map to da.ver=3, got %d", da.Ver)
		}
		if da.AgentKeyBinding == nil {
			t.Fatalf("da.ver=3 requires agent_key_binding")
		}
		if da.AgentKeyBinding.HashAlg != "sha-256" {
			t.Fatalf("hash_alg = %q, want sha-256", da.AgentKeyBinding.HashAlg)
		}
		if want := b64uEncode(keyHash); da.AgentKeyBinding.KeyHash != want {
			t.Fatalf("key_hash = %q, want %q", da.AgentKeyBinding.KeyHash, want)
		}
	})

	t.Run("v2_without_binding_is_rejected", func(t *testing.T) {
		o := opts()
		o.DAVersion = pki.DAVersion2
		if _, _, err := MapX509ToClaims(defaultXAIC(pki.DelegationAuthorized), o); err == nil {
			t.Fatalf("DA v2 without agentKeyBinding must be rejected")
		}
	})

	t.Run("v2_with_unknown_hash_algo_is_rejected", func(t *testing.T) {
		o := opts()
		o.DAVersion = pki.DAVersion2
		o.AgentKeyBinding = &pki.AgentKeyBinding{
			KeyHash:  make([]byte, 32),
			HashAlgo: pki.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}},
		}
		if _, _, err := MapX509ToClaims(defaultXAIC(pki.DelegationAuthorized), o); err == nil {
			t.Fatalf("unknown agentKeyBinding hash algorithm must be rejected")
		}
	})

	t.Run("unsupported_da_version_is_rejected", func(t *testing.T) {
		o := opts()
		o.DAVersion = 7
		if _, _, err := MapX509ToClaims(defaultXAIC(pki.DelegationAuthorized), o); err == nil {
			t.Fatalf("unsupported DA version must be rejected")
		}
	})
}
