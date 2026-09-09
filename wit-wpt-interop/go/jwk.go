// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

package interop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
)

// ECJWK 是 EC P-256 的 JWK（RFC 7517/7518）。D 仅私钥出现（wit_svid_key）。
type ECJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}

func jwkScalar(b *big.Int) string { return b64e(b.FillBytes(make([]byte, 32))) }
func scalarBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

func pubToJWK(pub *ecdsa.PublicKey) ECJWK {
	return ECJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   jwkScalar(pub.X),
		Y:   jwkScalar(pub.Y),
	}
}

func privToJWK(priv *ecdsa.PrivateKey) ECJWK {
	j := pubToJWK(&priv.PublicKey)
	j.D = jwkScalar(priv.D)
	return j
}

func jwkToPub(j ECJWK) (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported JWK: kty=%q crv=%q", j.Kty, j.Crv)
	}
	xb, err := b64d(j.X)
	if err != nil {
		return nil, err
	}
	yb, err := b64d(j.Y)
	if err != nil {
		return nil, err
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: scalarBig(xb), Y: scalarBig(yb)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("point not on P-256")
	}
	return pub, nil
}

func jwkToPriv(j ECJWK) (*ecdsa.PrivateKey, error) {
	if j.D == "" {
		return nil, fmt.Errorf("JWK has no private component d")
	}
	pub, err := jwkToPub(j)
	if err != nil {
		return nil, err
	}
	db, err := b64d(j.D)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: *pub, D: scalarBig(db)}, nil
}

// jkt 计算 RFC 7638 的 JWK Thumbprint：规范化成员按字典序、无空白
// {"crv","kty","x","y"}，SHA-256 后 base64url。
func jkt(pub *ecdsa.PublicKey) (string, error) {
	j := pubToJWK(pub)
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`,
		j.Crv, j.Kty, j.X, j.Y)
	sum := sha256.Sum256([]byte(canonical))
	return b64e(sum[:]), nil
}

// keyHash 计算 principal 的 key_hash：base64url(SHA-256(SPKI DER))。alg 必须 sha-256。
func keyHash(pub *ecdsa.PublicKey, alg string) (string, error) {
	if alg != "sha-256" {
		return "", fmt.Errorf("unsupported hash alg %q", alg)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return b64e(sum[:]), nil
}

func generateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
