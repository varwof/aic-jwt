// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

package interop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// ES256（P-256/SHA-256）JWS：签名为 R||S 各 32 字节共 64 字节原始格式
// （RFC 7518 §3.4）。本 harness 只实现非对称非 none 的 ES256。

func b64e(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func b64d(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// parseCompact 把 compact JWS 拆成 header/payload/signature 三个解码后的部分。
func parseCompact(s string) (header, payload, sig []byte, err error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("not a compact JWS (got %d parts)", len(parts))
	}
	header, err = b64d(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bad header segment: %w", err)
	}
	payload, err = b64d(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bad payload segment: %w", err)
	}
	sig, err = b64d(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bad signature segment: %w", err)
	}
	return header, payload, sig, nil
}

// signES256 对 data 做 SHA-256 后产生原始 R||S（各 32 字节）签名。
func signES256(data []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("ES256 requires a P-256 key")
	}
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// verifyES256 校验原始 R||S 签名。
func verifyES256(data, sig []byte, pub *ecdsa.PublicKey) error {
	if len(sig) != 64 {
		return errors.New("ES256 signature must be 64 bytes")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(data)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("invalid ECDSA signature")
	}
	return nil
}

// signJWS 构造 compact JWS：签名输入为 "h64.p64"。
func signJWS(header, payload []byte, key *ecdsa.PrivateKey) (string, error) {
	input := b64e(header) + "." + b64e(payload)
	sig, err := signES256([]byte(input), key)
	if err != nil {
		return "", err
	}
	return input + "." + b64e(sig), nil
}

// verifyJWS 验签并在成功后返回 header/payload 原文（header 视为受保护的）。
func verifyJWS(s string, pub *ecdsa.PublicKey) (header, payload []byte, err error) {
	h, p, sig, err := parseCompact(s)
	if err != nil {
		return nil, nil, err
	}
	input := b64e(h) + "." + b64e(p)
	if err := verifyES256([]byte(input), sig, pub); err != nil {
		return nil, nil, fmt.Errorf("signature verification failed: %w", err)
	}
	return h, p, nil
}

// parseHeader 只解析 header（不验签），用于检查 typ/alg/kid。
func parseHeader(s string, out any) error {
	h, _, _, err := parseCompact(s)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(h, out); err != nil {
		return fmt.Errorf("bad JWS header JSON: %w", err)
	}
	return nil
}
