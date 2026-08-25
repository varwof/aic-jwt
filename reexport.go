// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package aicjson is the standalone reference-implementation wrapper
// for draft-wei-aic-jwt-00.  All core logic (claims model, JWS,
// capability matching, constraints, key binding and the 11-step
// validation pipeline) lives in github.com/varwof/types/aicjwt; this
// package re-exports it under the aicjson API and keeps the OAuth
// protocol-layer simulation (oauth.go) for conformance scenarios.
package aicjson

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	pki "github.com/varwof/types"
	aj "github.com/varwof/types/aicjwt"
)

// ---- type aliases (single source of truth: types/aicjwt) -----------

type (
	Header               = aj.Header
	Audience             = aj.Audience
	Cnf                  = aj.Cnf
	StatusRef            = aj.StatusRef
	Principal            = aj.Principal
	Capability           = aj.Capability
	Extension            = aj.Extension
	AICClaims            = aj.AICClaims
	OuterClaims          = aj.OuterClaims
	Reason               = aj.Reason
	DAClaims             = aj.DAClaims
	DelegationPolicy     = aj.DelegationPolicy
	PAClaims             = aj.PAClaims
	JWK                  = aj.JWK
	RequestContext       = aj.RequestContext
	ConstraintEvaluator  = aj.ConstraintEvaluator
	CapabilityPlugin     = aj.CapabilityPlugin
	StatusChecker        = aj.StatusChecker
	NonceStore           = aj.NonceStore
	VerifyOptions        = aj.VerifyOptions
	Decision             = aj.Decision
	PrincipalKeyMaterial = aj.PrincipalKeyMaterial
	MemNonceStore        = aj.MemNonceStore
	NonceReuseError      = aj.NonceReuseError
)

// ---- constants -------------------------------------------------------

const (
	TypOuter                  = aj.TypOuter
	TypDA                     = aj.TypDA
	TypPA                     = aj.TypPA
	ModeAuthorized            = aj.ModeAuthorized
	ModeRepresentative        = aj.ModeRepresentative
	ConstraintScheme          = aj.ConstraintScheme
	MaxLifetime               = aj.MaxLifetime
	AllowedModeRepresentative = aj.AllowedModeRepresentative
)

// ---- shared maps -----------------------------------------------------

var (
	AllowedAlgs          = aj.AllowedAlgs
	ImplementedAlgs      = aj.ImplementedAlgs
	SupportedHashAlgs    = aj.SupportedHashAlgs
	BuiltinConstraintIDs = aj.BuiltinConstraintIDs
)

// ---- function re-exports ---------------------------------------------

func SignCompact(header, payload []byte, alg string, key crypto.Signer) (string, error) {
	return aj.SignCompact(header, payload, alg, key)
}

func ParseCompact(token string) ([]byte, []byte, []byte, error) {
	return aj.ParseCompact(token)
}

func VerifyCompact(token, alg string, pub crypto.PublicKey) error {
	return aj.VerifyCompact(token, alg, pub)
}

func MatchCapabilities(allowed []Capability, req Capability) bool {
	return aj.MatchCapabilities(allowed, req)
}

func ParamsWithinGrant(grant, agent json.RawMessage) (bool, error) {
	return aj.ParamsWithinGrant(grant, agent)
}

func EvaluateConstraints(cs []Capability, ctx RequestContext, strict bool) ([]string, error) {
	return aj.EvaluateConstraints(cs, ctx, strict)
}

func SPKIHash(cert *x509.Certificate, hashAlg string) (string, error) {
	return aj.SPKIHash(cert, hashAlg)
}

func SPKIHashPub(pub crypto.PublicKey, hashAlg string) (string, error) {
	return aj.SPKIHashPub(pub, hashAlg)
}

func JWKThumbprint(j JWK) (string, error) { return aj.JWKThumbprint(j) }

func PublicKeyToJWK(pub crypto.PublicKey) (JWK, error) { return aj.PublicKeyToJWK(pub) }

func JWKToPublic(j JWK) (crypto.PublicKey, error) { return aj.JWKToPublic(j) }

func KeyHashOf(pub crypto.PublicKey, hashAlg string) (string, error) {
	return aj.KeyHashOf(pub, hashAlg)
}

func ParseJWK(b []byte) (JWK, error) { return aj.ParseJWK(b) }

func Validate(token string, opts VerifyOptions) (*Decision, error) {
	return aj.Validate(token, opts)
}

func ValidateDA(daToken string, opts VerifyOptions) (*DAClaims, error) {
	return aj.ValidateDA(daToken, opts)
}

func JSONRawEqual(a, b json.RawMessage) (bool, error) { return aj.JSONRawEqual(a, b) }

func checkHeader(h Header, expectedTyp string) error { return aj.CheckHeader(h, expectedTyp) }

func capabilitySubset(agent Capability, grants []Capability) bool {
	return aj.CapabilitySubset(agent, grants)
}

func CapToPKI(c Capability) pki.Capability { return aj.CapToPKI(c) }

func PKIToCap(c pki.Capability) Capability { return aj.PKIToCap(c) }

// ---- local helpers retained for the protocol layer -------------------

func b64uEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64uDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
