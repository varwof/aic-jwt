// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjson

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// draft -02 Section 10.2: "When the DA is da.ver=3, the AS MUST verify
// that the key identified by cnf matches agent_key_binding before
// signing."  IssueFromDA puts KeyHashOf(agentPub, "jkt") into cnf, so
// agentPub is the key the token will name; signing without checking it
// against the principal-signed binding lets the holder of a valid ver=3
// DA mint a token whose cnf points at a key the principal never bound.
func TestIssueFromDAVer3BindsAgentKey(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:*"}}

	bindingOf := func(t *testing.T, key *ecdsa.PrivateKey) *AgentKeyBinding {
		t.Helper()
		h, err := KeyHashOf(&key.PublicKey, "sha-256")
		if err != nil {
			t.Fatal(err)
		}
		return &AgentKeyBinding{HashAlg: "sha-256", KeyHash: h}
	}

	t.Run("matching_agent_key_is_accepted", func(t *testing.T) {
		daTok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 3
			d.AgentKeyBinding = bindingOf(t, env.agentKey)
		})
		if _, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, env.now); err != nil {
			t.Fatalf("ver=3 with a matching agent key should be issued: %v", err)
		}
	})

	t.Run("substituted_agent_key_is_refused", func(t *testing.T) {
		attacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		daTok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
			d.Ver = 3
			d.AgentKeyBinding = bindingOf(t, env.agentKey)
		})
		_, _, err = env.issuer.IssueFromDA(daTok, &attacker.PublicKey,
			[]string{"https://rs.example.com"}, env.now)
		if err == nil {
			t.Fatal("AS signed a ver=3 token whose cnf names a key the DA never bound")
		}
		requireErrContains(t, err, "agent_key_binding")
	})

	t.Run("ver2_carries_no_binding", func(t *testing.T) {
		// ver=2 has no agent_key_binding, so there is nothing to cross-check
		// and the substituted key is still accepted (legacy substitution
		// mitigations, draft Section 13).
		attacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
		if _, _, err := env.issuer.IssueFromDA(daTok, &attacker.PublicKey,
			[]string{"https://rs.example.com"}, env.now); err != nil {
			t.Fatalf("ver=2 must remain issuable without a binding check: %v", err)
		}
	})
}
