// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

package interop

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// env 组装一次完整场景所需的密钥与组件（每行独立、不共享状态）。
type env struct {
	principal *ecdsa.PrivateKey
	issuerKey *ecdsa.PrivateKey
	iss       *Issuer
	ver       *Verifier
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pk := mustKey(t)
	ik := mustKey(t)
	iss := NewIssuer("example.org", ik, "wk-01")
	ver := &Verifier{
		TrustBundle: map[string]*ecdsa.PublicKey{"wk-01": &ik.PublicKey},
		Replay:      NewMemoryReplayStore(),
		Now:         func() int64 { return now0 },
	}
	return &env{principal: pk, issuerKey: ik, iss: iss, ver: ver}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// capOf 构造 Capability，params 经 JSON 规范化（数字统一成 float64）。
func capOf(scheme, id string, params any) Capability {
	c := Capability{Scheme: scheme, ID: id}
	if params == nil {
		return c
	}
	b, _ := json.Marshal(params)
	_ = json.Unmarshal(b, &c.Params)
	return c
}

// principalOf 由密钥派生 principal 的 key_hash。
func principalOf(priv *ecdsa.PrivateKey, realm, id string) Principal {
	kh, err := keyHash(&priv.PublicKey, "sha-256")
	if err != nil {
		panic(err)
	}
	return Principal{Realm: realm, ID: id, KeyHash: kh, HashAlg: "sha-256"}
}

func makeDA(p Principal, agentID string, caps []Capability, mode string, lifetime int, now int64) DA {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return DA{
		Ver:               1,
		AgentID:           agentID,
		Principal:         p,
		Reason:            Reason{Code: "access", Desc: "grid access granted"},
		Capabilities:      caps,
		DelegationMode:    mode,
		RequestedLifetime: lifetime,
		TS:                now,
		Nonce:             b64e(nonce),
	}
}

func makePA(p Principal, grants []Capability) PA {
	return PA{Ver: 1, Principal: p, Grants: grants}
}

func (e *env) daCompact(t *testing.T, d DA) string {
	t.Helper()
	s, err := signArtifact("da+jwt", d, e.principal)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *env) paCompact(t *testing.T, p PA) string {
	t.Helper()
	s, err := signArtifact("pa+jwt", p, e.principal)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// reSignWIT 用发放服务密钥对修改后的 claims 重新签名（测试专用：模拟"改了字节
// 但仍是有效生产产物"，从而把 wth mismatch 暴露在验签之后）。
func (e *env) reSignWIT(t *testing.T, wit string, mutate func(map[string]any)) string {
	t.Helper()
	h, p, _, err := parseCompact(wit)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(p, &claims); err != nil {
		t.Fatal(err)
	}
	mutate(claims)
	tok, err := signJWS(h, mustJSON(claims), e.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

const (
	now0      = int64(1_700_000_000)
	targetURI = "https://rs.example.com/orders"
)

// happyGrant 构造 S1 的合法代表授权：DA max_rows=500，PA grants max_rows=1000。
func (e *env) happyGrant(t *testing.T) *WITGrant {
	t.Helper()
	p := principalOf(e.principal, "realm.example", "alice")
	grants := []Capability{capOf("mysql", "query", map[string]any{"max_rows": 1000})}
	caps := []Capability{capOf("mysql", "query", map[string]any{"max_rows": 500})}
	da := makeDA(p, "agent-1", caps, "representative", 3600, now0)
	pa := makePA(p, grants)
	g, err := e.iss.Issue(e.daCompact(t, da), e.paCompact(t, pa), "agent-1", now0)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// happyInputs 返回 S1 的完整验证输入（WIT+WPT+Request+opts）。
func (e *env) happyInputs(t *testing.T) (string, string, Request, VerifyOpts) {
	t.Helper()
	g := e.happyGrant(t)
	witKey, err := jwkToPriv(g.WITPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	wpt, err := MintWPT(g.WITSVID, "GET", targetURI, now0, witKey)
	if err != nil {
		t.Fatal(err)
	}
	rc := capOf("mysql", "query", map[string]any{"max_rows": 500})
	req := Request{Method: "GET", TargetURI: targetURI, Now: now0, RequestedCapability: &rc}
	opts := VerifyOpts{
		Entitlement: g.Entitlement,
		Policy: func(ent []Capability, c Capability) error {
			ok, _ := capabilityCoveredIn(c, ent)
			if !ok {
				return errors.New("requested capability not in entitlement")
			}
			return nil
		},
	}
	return g.WITSVID, wpt, req, opts
}

func entitlementPolicy() func([]Capability, Capability) error {
	return func(ent []Capability, c Capability) error {
		ok, _ := capabilityCoveredIn(c, ent)
		if !ok {
			return errors.New("requested capability not in entitlement")
		}
		return nil
	}
}

type run struct {
	wit, wpt string
	req      Request
	opts     VerifyOpts
	// issueErr 非空 = 场景应在签发阶段被拒（如 S2）。
	issueErr string
}

func TestScenarios(t *testing.T) {
	cases := []struct {
		id, name   string
		wantPermit bool
		wantReason string
		prepare    func(t *testing.T, e *env) *run
	}{
		{"S1", "happy path", true, "", func(t *testing.T, e *env) *run {
			wit, wpt, req, opts := e.happyInputs(t)
			return &run{wit: wit, wpt: wpt, req: req, opts: opts}
		}},
		{"S2", "agent caps exceed P_grants (max_rows 5000 > 1000)", false, "subset", func(t *testing.T, e *env) *run {
			p := principalOf(e.principal, "realm.example", "alice")
			grants := []Capability{capOf("mysql", "query", map[string]any{"max_rows": 1000})}
			caps := []Capability{capOf("mysql", "query", map[string]any{"max_rows": 5000})}
			da := makeDA(p, "agent-1", caps, "representative", 3600, now0)
			pa := makePA(p, grants)
			_, err := e.iss.Issue(e.daCompact(t, da), e.paCompact(t, pa), "agent-1", now0)
			return &run{issueErr: errString(err)}
		}},
		{"S3", "tampered WIT + original WPT -> wth mismatch", false, "wth mismatch", func(t *testing.T, e *env) *run {
			wit, wpt, req, opts := e.happyInputs(t)
			bad := e.reSignWIT(t, wit, func(c map[string]any) { c["tamper_flag"] = true })
			return &run{wit: bad, wpt: wpt, req: req, opts: opts}
		}},
		{"S4", "WPT signed with a different key", false, "pop", func(t *testing.T, e *env) *run {
			wit, wpt, req, opts := e.happyInputs(t)
			other, _ := generateKey()
			bad, err := MintWPT(wit, "GET", targetURI, now0, other)
			if err != nil {
				t.Fatal(err)
			}
			_ = wpt
			return &run{wit: wit, wpt: bad, req: req, opts: opts}
		}},
		{"S5", "WPT aud != request target URI", false, "aud mismatch", func(t *testing.T, e *env) *run {
			wit, wpt, _, opts := e.happyInputs(t)
			req := Request{Method: "POST", TargetURI: "https://rs.example.com/invoices", Now: now0}
			return &run{wit: wit, wpt: wpt, req: req, opts: opts}
		}},
		{"S6", "WPT expired (now > exp)", false, "expired", func(t *testing.T, e *env) *run {
			wit, wpt, req, opts := e.happyInputs(t)
			e.ver.Now = func() int64 { return now0 + 121 } // WPT exp = now0+120
			req.Now = now0 + 121
			return &run{wit: wit, wpt: wpt, req: req, opts: opts}
		}},
		{"S7", "WPT replay", false, "replay", func(t *testing.T, e *env) *run {
			wit, wpt, req, opts := e.happyInputs(t)
			if d := e.ver.Verify(wit, wpt, req, opts); !d.Permit {
				t.Fatalf("first verify should be PERMIT: %v", d.Reason)
			}
			return &run{wit: wit, wpt: wpt, req: req, opts: opts}
		}},
		{"S8", "no WPT (bearer misuse)", false, "pop required", func(t *testing.T, e *env) *run {
			wit, _, req, opts := e.happyInputs(t)
			e.ver.Replay = NewMemoryReplayStore()
			return &run{wit: wit, wpt: "", req: req, opts: opts}
		}},
		{"S9", "WIT carries aud (WIT-SVID MUST NOT)", false, "aud-in-wit", func(t *testing.T, e *env) *run {
			wit, wpt, req, opts := e.happyInputs(t)
			bad := e.reSignWIT(t, wit, func(c map[string]any) { c["aud"] = targetURI })
			return &run{wit: bad, wpt: wpt, req: req, opts: opts}
		}},
		{"S10", "requested capability outside entitlement -> policy deny", false, "policy:", func(t *testing.T, e *env) *run {
			wit, wpt, _, opts := e.happyInputs(t)
			rc := capOf("mysql", "drop", nil)
			req := Request{Method: "POST", TargetURI: targetURI, Now: now0, RequestedCapability: &rc}
			return &run{wit: wit, wpt: wpt, req: req, opts: opts}
		}},
		{"S11", "WPT alg != WIT cnf.jwk.alg", false, "alg mismatch", func(t *testing.T, e *env) *run {
			wit, _, _, opts := e.happyInputs(t)
			g := e.happyGrant(t)
			witKey, err := jwkToPriv(g.WITPrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			valid, _ := MintWPT(wit, "GET", targetURI, now0, witKey)
			_, p, _, err := parseCompact(valid)
			if err != nil {
				t.Fatal(err)
			}
			hdr := map[string]any{"typ": "wpt+jwt", "alg": "RS256"}
			bad, err := signJWS(mustJSON(hdr), p, witKey)
			if err != nil {
				t.Fatal(err)
			}
			req := Request{Method: "GET", TargetURI: targetURI, Now: now0}
			return &run{wit: wit, wpt: bad, req: req, opts: opts}
		}},
	}

	for _, c := range cases {
		t.Run(c.id+" "+c.name, func(t *testing.T) {
			e := newEnv(t)
			r := c.prepare(t, e)
			if r.issueErr != "" {
				if c.wantPermit {
					t.Fatalf("expected issuance OK, got error %q", r.issueErr)
				}
				expectContains(t, r.issueErr, c.wantReason)
				return
			}
			if c.wantReason == "" && c.wantPermit == false {
				t.Fatalf("test case must specify wantReason or wantPermit=true")
			}
			d := e.ver.Verify(r.wit, r.wpt, r.req, r.opts)
			if d.Permit != c.wantPermit {
				t.Fatalf("Permit=%v want %v; reason=%q checks=%+v",
					d.Permit, c.wantPermit, d.Reason, d.Checks)
			}
			if !d.Permit {
				expectContains(t, d.Reason, c.wantReason)
			}
		})
	}
}

func expectContains(t *testing.T, s, sub string) {
	t.Helper()
	if sub != "" && !strings.Contains(s, sub) {
		t.Fatalf("reason %q missing expected substring %q", s, sub)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
