// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

package interop

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ReplayStore 负责 jti 防重放：同一 verifier 同一 jti 只能通过一次。
type ReplayStore interface {
	// CheckAndAdd 在窗口（由 exp 决定）内登记 jti；已见则返回错误。
	CheckAndAdd(jti string, exp int64) error
}

// MemoryReplayStore 是测试用的内存实现。
type MemoryReplayStore struct {
	mu   sync.Mutex
	seen map[string]bool
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{seen: map[string]bool{}}
}

func (m *MemoryReplayStore) CheckAndAdd(jti string, exp int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[jti] {
		return errors.New("replay: jti already seen")
	}
	m.seen[jti] = true
	return nil
}

// VerifyOpts 是 Verify 的部署侧配置：身份白名单钩子与本地策略钩子。
type VerifyOpts struct {
	// AllowedIdentity 校验 WIT sub；nil 时默认要求 sub 以 "spiffe://" 开头。
	AllowedIdentity func(spiffeID string) bool
	// Policy 在请求带 requested_capability 时按 issuance 记录的 entitlement
	// 做 capability 判定；返回非 nil 错误即 DENY（reason 前缀 "policy:"）。
	Policy func(entitlement []Capability, req Capability) error
	// Entitlement 是签发时记录的 entitlement（来自 WITGrant）。
	Entitlement []Capability
}

// Verifier 是资源服务器（WIMSE 风格）验证管线。
type Verifier struct {
	// TrustBundle 是信任 bundle：WIT header kid -> 公钥。
	TrustBundle map[string]*ecdsa.PublicKey
	// Replay 为 nil 时自动使用 NewMemoryReplayStore()。
	Replay ReplayStore
	// Now 默认 time.Now().Unix()；测试注入固定时钟。
	Now func() int64
}

func (v *Verifier) now() int64 {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now().Unix()
}

// MintWPT 由 agent 构造 PoP 凭证（用 WIT 的 cnf 私钥对 WPT 签名）。
// 呈现方式为 Authorization: WPT <token>，与其它认证 scheme 互斥。
func MintWPT(wit, method, targetURI string, now int64, priv *ecdsa.PrivateKey) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(wit))
	header := map[string]any{"typ": "wpt+jwt", "alg": "ES256"}
	claims := map[string]any{
		"aud": targetURI,
		"exp": now + 120, // 短寿命（秒级，<=300）
		"iat": now,
		"jti": b64e(jti),
		"wth": b64e(sum[:]),
	}
	return signJWS(mustJSON(header), mustJSON(claims), priv)
}

// Verify 执行 §5.2 的验证管线，返回逐项检查报告与 PERMIT/DENY。
// wpt 是请求中 Authorization: WPT <token> 提取出的 token；空串即视为
// bearer 误用（PoP required）。
func (v *Verifier) Verify(wit, wpt string, req Request, opts VerifyOpts) Decision {
	var fail *CheckResult
	checks := make([]CheckResult, 0, 8)
	check := func(step string, ok bool, detail string) {
		c := CheckResult{Step: step, OK: ok, Detail: detail}
		checks = append(checks, c)
		if fail == nil && !ok {
			fail = &c
		}
	}

	// 1) WIT header 检查（typ/alg/kid；拒绝 none 与非对称之外的算法）。
	allowAlgs := map[string]bool{"ES256": true, "RS256": true, "PS256": true}
	var withdr struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := parseHeader(wit, &withdr); err != nil {
		check("header", false, "header: "+err.Error())
		return finish(checks, fail)
	}
	if withdr.Typ != "wit+jwt" {
		check("header", false, "header: bad typ "+withdr.Typ)
		return finish(checks, fail)
	}
	if !allowAlgs[withdr.Alg] {
		check("header", false, "header: alg "+withdr.Alg+" not allowed (must be asymmetric, non-none)")
		return finish(checks, fail)
	}
	if withdr.Kid == "" {
		check("header", false, "header: kid is REQUIRED")
		return finish(checks, fail)
	}
	bundlePub, ok := v.TrustBundle[withdr.Kid]
	if !ok || bundlePub == nil {
		check("header", false, "header: kid "+withdr.Kid+" not in trust bundle")
		return finish(checks, fail)
	}
	check("header", true, "typ=wit+jwt alg="+withdr.Alg+" kid="+withdr.Kid)

	// 2) WIT 验签。
	_, witPayload, err := verifyJWS(wit, bundlePub)
	if err != nil {
		check("wit-signature", false, "wit-signature: "+err.Error())
		return finish(checks, fail)
	}
	check("wit-signature", true, "verified with bundle kid "+withdr.Kid)

	// 3) WIT 时间。
	now := v.now()
	var witC struct {
		Sub string `json:"sub"`
		Iss string `json:"iss"`
		Aud any    `json:"aud"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Cnf struct {
			JWK ECJWK  `json:"jwk"`
			Alg string `json:"alg"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(witPayload, &witC); err != nil {
		check("wit-time", false, "wit-time: payload JSON: "+err.Error())
		return finish(checks, fail)
	}
	if witC.Exp == 0 || now >= witC.Exp {
		check("wit-time", false, "wit-time: expired (now="+int64Str(now)+" exp="+int64Str(witC.Exp)+")")
		return finish(checks, fail)
	}
	if witC.Iat != 0 && now < witC.Iat {
		check("wit-time", false, "wit-time: not yet valid (iat="+int64Str(witC.Iat)+")")
		return finish(checks, fail)
	}
	check("wit-time", true, "valid at now "+int64Str(now))

	// 4) WIT claims 规则：sub=spiffe://、aud 禁止、cnf.jwk(+alg) REQUIRED。
	allowed := func(s string) bool { return strings.HasPrefix(s, "spiffe://") }
	if opts.AllowedIdentity != nil {
		allowed = opts.AllowedIdentity
	}
	if !strings.HasPrefix(witC.Sub, "spiffe://") || !allowed(witC.Sub) {
		check("wit-claims", false, "wit-claims: sub "+witC.Sub+" is not an allowed spiffe:// identity")
		return finish(checks, fail)
	}
	if witC.Aud != nil {
		check("wit-claims", false, "wit-claims: aud-in-wit (WIT-SVID MUST NOT carry aud)")
		return finish(checks, fail)
	}
	if witC.Cnf.JWK.Kty == "" {
		check("wit-claims", false, "wit-claims: cnf.jwk is REQUIRED")
		return finish(checks, fail)
	}
	if witC.Cnf.Alg != withdr.Alg {
		check("wit-claims", false, "wit-claims: cnf.alg "+witC.Cnf.Alg+" != header alg "+withdr.Alg)
		return finish(checks, fail)
	}
	cnfPub, err := jwkToPub(witC.Cnf.JWK)
	if err != nil {
		check("wit-claims", false, "wit-claims: bad cnf.jwk: "+err.Error())
		return finish(checks, fail)
	}
	check("wit-claims", true, "sub="+witC.Sub+" cnf.jwk present")

	// 7) PoP 呈现：没有 WPT 即 DENY（bearer 误用）。
	if wpt == "" {
		check("pop", false, "pop required: missing WPT (WIT MUST NOT be used as a bearer)")
		return finish(checks, fail)
	}

	// 5) WPT 验签：公有 cnf.jwk，算法必须一致。
	var wpthdr struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}
	if err := parseHeader(wpt, &wpthdr); err != nil {
		check("pop", false, "pop: bad WPT header: "+err.Error())
		return finish(checks, fail)
	}
	if wpthdr.Typ != "wpt+jwt" {
		check("pop", false, "pop: bad WPT typ "+wpthdr.Typ)
		return finish(checks, fail)
	}
	if wpthdr.Alg != witC.Cnf.Alg {
		check("pop", false, "pop: alg mismatch (WPT alg "+wpthdr.Alg+" != cnf.jwk.alg "+witC.Cnf.Alg+")")
		return finish(checks, fail)
	}
	_, wptPayload, err := verifyJWS(wpt, cnfPub)
	if err != nil {
		check("pop", false, "pop: WPT signature verification failed: "+err.Error())
		return finish(checks, fail)
	}
	check("pop", true, "WPT verified with WIT cnf.jwk")

	// 6) WPT claims：aud/exp(短)/jti(16 字节唯一)/wth。
	var wptC struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Jti string `json:"jti"`
		Wth string `json:"wth"`
	}
	if err := json.Unmarshal(wptPayload, &wptC); err != nil {
		check("wpt", false, "wpt: payload JSON: "+err.Error())
		return finish(checks, fail)
	}
	if wptC.Aud != req.TargetURI {
		check("wpt", false, "wpt: aud mismatch (wpt aud "+wptC.Aud+" != request target "+req.TargetURI+")")
		return finish(checks, fail)
	}
	if wptC.Exp == 0 || now >= wptC.Exp {
		check("wpt", false, "wpt: expired (now="+int64Str(now)+" exp="+int64Str(wptC.Exp)+")")
		return finish(checks, fail)
	}
	if wptC.Exp-now > 300 {
		check("wpt", false, "wpt: exp not short-lived ("+int64Str(wptC.Exp-now)+"s > 300s)")
		return finish(checks, fail)
	}
	jtib, err := b64d(wptC.Jti)
	if err != nil || len(jtib) != 16 {
		check("wpt", false, "wpt: jti must be 128-bit base64url")
		return finish(checks, fail)
	}
	store := v.Replay
	if store == nil {
		store = NewMemoryReplayStore()
	}
	if err := store.CheckAndAdd(wptC.Jti, wptC.Exp); err != nil {
		check("wpt", false, "wpt: "+err.Error())
		return finish(checks, fail)
	}
	gotDigest := sum256([]byte(wit))
	if b64e(gotDigest[:]) != wptC.Wth {
		check("wpt", false, "wpt: wth mismatch (bound token hash differs)")
		return finish(checks, fail)
	}
	check("wpt", true, "aud/exp/jti/wth validated")

	// 8) 部署策略：requested_capability 超出 entitlement 即 DENY。
	if opts.Policy != nil && req.RequestedCapability != nil {
		if err := opts.Policy(opts.Entitlement, *req.RequestedCapability); err != nil {
			check("policy", false, "policy: "+err.Error())
			return finish(checks, fail)
		}
		check("policy", true, "requested capability within entitlement")
	}
	return finish(checks, fail)
}

func finish(checks []CheckResult, fail *CheckResult) Decision {
	if fail == nil {
		return Decision{Permit: true, Reason: "PERMIT", Checks: checks}
	}
	c := *fail
	return Decision{Permit: false, Reason: c.Detail, Checks: checks}
}

func sum256(b []byte) [32]byte { return sha256.Sum256(b) }

func int64Str(v int64) string { return fmt.Sprintf("%d", v) }
