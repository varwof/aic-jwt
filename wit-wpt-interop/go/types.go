// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// Package interop 实现 AIC DA/PA → WIT-SVID 签发 → WPT PoP → WIMSE 风格验证的
// 互操作 harness（Go 单实现，仅标准库）。与 ts/ 子目录是同一套语义的镜像。
package interop

import "encoding/json"

// Capability 是 AIC 的能力（scheme + id + params）。
// params 可为 object/array/number/string/bool；number 一律按 JSON 数字（float64）。
type Capability struct {
	Scheme string `json:"scheme"`
	ID     string `json:"id"`
	Params any    `json:"params,omitempty"`
}

// Constraint 是 AIC 约束。Type 必须在本 harness 已知集合内，未知即 fail-closed。
type Constraint struct {
	Type   string `json:"type"`
	Params any    `json:"params,omitempty"`
}

// Principal 是 AIC principal（人类/代表主体）。
type Principal struct {
	Realm   string `json:"realm"`
	ID      string `json:"id"`
	KeyHash string `json:"key_hash"` // base64url(SHA-256(SPKI DER))
	HashAlg string `json:"hash_alg"` // "sha-256"
}

// Reason 是 DA 的授权原因描述。
type Reason struct {
	Code string `json:"code"`
	Desc string `json:"desc"`
}

// DA 是 AIC 委托授权（principal 签名）。签名见 issuer.go 的 signArtifact。
type DA struct {
	Ver               int          `json:"ver"`
	AgentID           string       `json:"agent_id"`
	Principal         Principal    `json:"principal"`
	Reason            Reason       `json:"reason"`
	Capabilities      []Capability `json:"capabilities"`
	DelegationMode    string       `json:"delegation_mode"` // "authorized" | "representative"
	Constraints       []Constraint `json:"constraints"`
	RequestedLifetime int          `json:"requested_lifetime"` // 1..86400 秒
	TS                int64        `json:"ts"`
	Nonce             string       `json:"nonce"` // 32 字节 base64url 无填充
}

// PA 是 AIC 代表代理授权（仅 representative 模式需要）。
type PA struct {
	Ver         int          `json:"ver"`
	Principal   Principal    `json:"principal"`
	Grants      []Capability `json:"grants"`
	Constraints []Constraint `json:"constraints"`
}

// WITGrant 是 AIC-aware 发放服务的产物（对应 FetchWITSVID 响应中的 WITSVID）。
type WITGrant struct {
	SpiffeID      string       `json:"spiffe_id"`
	WITSVID       string       `json:"wit_svid"` // compact JWS
	WITPrivateKey ECJWK        `json:"wit_private_key"`
	Kid           string       `json:"kid"`
	Entitlement   []Capability `json:"entitlement"`
	Exp           int64        `json:"exp"`
}

// Request 是 agent 构造的 HTTP 请求（target_uri 不含 query/fragment）。
type Request struct {
	Method              string
	TargetURI           string
	Body                []byte
	RequestedCapability *Capability
	Now                 int64
}

// CheckResult 是验证管线中的单步结果（对齐 draft-01 §11 风格，便于逐项展示）。
type CheckResult struct {
	Step   string `json:"step"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Decision 是整个验证的结论。
type Decision struct {
	Permit bool          `json:"permit"`
	Reason string        `json:"reason"`
	Checks []CheckResult `json:"checks"`
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
