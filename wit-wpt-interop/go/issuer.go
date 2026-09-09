// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

package interop

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Issuer 是 AIC-aware 的 SPIFFE 侧发放服务：签发 WIT-SVID 前校验 DA/PA
// （AIC 决策落在 issuance-control，不进入 WIT claims）。
type Issuer struct {
	TrustDomain string
	SigningKey  *ecdsa.PrivateKey // WIT-SVID 签发私钥（信任 bundle 的公钥相应对）
	SigningKid  string            // WIT header 的 kid
}

func NewIssuer(trustDomain string, key *ecdsa.PrivateKey, kid string) *Issuer {
	return &Issuer{TrustDomain: trustDomain, SigningKey: key, SigningKid: kid}
}

// Issue 校验 DA（必须）+ PA（representative 模式必须）后签发 WIT-SVID。
// 任何一步失败都返回 nil grant 与可读错误（不发半成品）。
// da/pa 均为自包含 compact JWS：header 内嵌签发者公钥 JWK（kid 不要求），
// 发放服务先取 header 公钥验签，再核对 principal.key_hash 绑定。
func (iss *Issuer) Issue(da string, paOpt string, agentID string, now int64) (*WITGrant, error) {
	daPayload, daPub, err := parseArtifact(da, "da+jwt")
	if err != nil {
		return nil, fmt.Errorf("DA: %w", err)
	}
	var d DA
	if err := json.Unmarshal(daPayload, &d); err != nil {
		return nil, fmt.Errorf("DA payload: %w", err)
	}
	if d.Ver != 1 {
		return nil, fmt.Errorf("DA: unsupported ver %d", d.Ver)
	}
	// 1. 校验 principal.key_hash 与签名公钥一致。
	if err := checkKeyHash(daPub, d.Principal); err != nil {
		return nil, fmt.Errorf("DA: %w", err)
	}
	// agent_id 必须是请求的 SPIFFE ID 的路径段。
	if agentID == "" {
		return nil, errors.New("DA: agentID is empty")
	}
	if d.AgentID != agentID {
		return nil, fmt.Errorf("DA: agent_id %q != requested identity path %q", d.AgentID, agentID)
	}
	if fields := strings.Fields(agentID); len(fields) != 1 {
		return nil, fmt.Errorf("DA: agent_id %q has invalid characters", agentID)
	}
	if d.RequestedLifetime < 1 || d.RequestedLifetime > 86400 {
		return nil, fmt.Errorf("DA: requested_lifetime %d out of range [1,86400]", d.RequestedLifetime)
	}
	if nb, err := b64d(d.Nonce); err != nil || len(nb) != 32 {
		return nil, errors.New("DA: nonce must be 32 bytes base64url")
	}
	if d.DelegationMode != "authorized" && d.DelegationMode != "representative" {
		return nil, fmt.Errorf("DA: unsupported delegation_mode %q", d.DelegationMode)
	}
	if err := ValidateConstraints(d.Constraints); err != nil {
		return nil, fmt.Errorf("DA: %w", err)
	}

	var grants []Capability
	if d.DelegationMode == "representative" {
		// 2. representative 必须带 PA，且与 DA 同一 principal。
		if paOpt == "" {
			return nil, errors.New("representative DA requires a PA")
		}
		paPayload, _, err := parseArtifact(paOpt, "pa+jwt")
		if err != nil {
			return nil, fmt.Errorf("PA: %w", err)
		}
		var p PA
		if err := json.Unmarshal(paPayload, &p); err != nil {
			return nil, fmt.Errorf("PA payload: %w", err)
		}
		if p.Ver != 1 {
			return nil, fmt.Errorf("PA: unsupported ver %d", p.Ver)
		}
		if p.Principal.KeyHash != d.Principal.KeyHash || p.Principal.HashAlg != d.Principal.HashAlg {
			return nil, errors.New("PA principal does not match DA principal")
		}
		if err := ValidateConstraints(p.Constraints); err != nil {
			return nil, fmt.Errorf("PA: %w", err)
		}
		// 3. C_agent ⊆ P_grants。
		ok, detail := capabilitiesCovered(d.Capabilities, p.Grants)
		if !ok {
			return nil, fmt.Errorf("issuance denied: %s", detail)
		}
		grants = p.Grants
	} else {
		// authorized：DA 即授权快照，entitlement 直接取 DA capabilities。
		grants = d.Capabilities
		if paOpt != "" {
			return nil, errors.New("authorized DA must not carry a PA")
		}
	}

	// 4. 生成 WIT 密钥对（模拟 wit_svid_key 随响应下发）。
	//    WIT 的 cnf 私钥与 AIC DA 绑定的 agent 密钥是 issuance-time 映射，非同一把。
	witKey, err := generateKey()
	if err != nil {
		return nil, err
	}

	spiffeID := "spiffe://" + iss.TrustDomain + "/agent/" + agentID
	exp := now + int64(d.RequestedLifetime)
	witClaims := map[string]any{
		"iss": spiffeID,
		"sub": spiffeID,
		"iat": now,
		"exp": exp,
		"cnf": map[string]any{
			"jwk": pubToJWK(&witKey.PublicKey),
			"alg": "ES256",
		},
	}
	witHeader := map[string]any{
		"typ": "wit+jwt",
		"alg": "ES256",
		"kid": iss.SigningKid,
	}
	token, err := signJWS(mustJSON(witHeader), mustJSON(witClaims), iss.SigningKey)
	if err != nil {
		return nil, err
	}

	// 5. 组装 grant（只在全部成功后构造）。
	return &WITGrant{
		SpiffeID:      spiffeID,
		WITSVID:       token,
		WITPrivateKey: privToJWK(witKey),
		Kid:           iss.SigningKid,
		Entitlement:   grants,
		Exp:           exp,
	}, nil
}

// signArtifact 为 DA/PA 签发自包含 compact JWS，header 内嵌签发者公钥。
func signArtifact(typ string, claims any, priv *ecdsa.PrivateKey) (string, error) {
	pub := &priv.PublicKey
	header := map[string]any{
		"typ": typ,
		"alg": "ES256",
		"jwk": pubToJWK(pub),
	}
	return signJWS(mustJSON(header), mustJSON(claims), priv)
}

// parseArtifact 验签并返回 payload 与签名公钥（公钥取自 header 的 jwk）。
func parseArtifact(s, wantTyp string) (payload []byte, pub *ecdsa.PublicKey, err error) {
	var hdr struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		JWK ECJWK  `json:"jwk"`
	}
	if err := parseHeader(s, &hdr); err != nil {
		return nil, nil, err
	}
	if hdr.Typ != wantTyp {
		return nil, nil, fmt.Errorf("bad typ %q (want %q)", hdr.Typ, wantTyp)
	}
	if hdr.Alg != "ES256" {
		return nil, nil, fmt.Errorf("unsupported alg %q", hdr.Alg)
	}
	pub, err = jwkToPub(hdr.JWK)
	if err != nil {
		return nil, nil, err
	}
	_, payload, err = verifyJWS(s, pub)
	if err != nil {
		return nil, nil, err
	}
	return payload, pub, nil
}

func checkKeyHash(pub *ecdsa.PublicKey, p Principal) error {
	if p.HashAlg != "sha-256" {
		return fmt.Errorf("unsupported principal hash_alg %q", p.HashAlg)
	}
	h, err := keyHash(pub, p.HashAlg)
	if err != nil {
		return err
	}
	if h != p.KeyHash {
		return errors.New("principal.key_hash does not match DA signing key")
	}
	return nil
}
