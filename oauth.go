// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjson

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuth grant and token type identifiers used by this reference
// implementation.
const (
	GrantTypeJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantTypeAuthCode      = "authorization_code"
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	AssertionTypeJWT       = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	TokenTypeAIC           = "urn:ietf:params:oauth:token-type:aic+jwt"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeBearer        = "Bearer"
)

// TokenRequest models the OAuth token endpoint request parameters used
// by the supported flows (RFC 6749, RFC 7523, RFC 8693, OBO).
type TokenRequest struct {
	GrantType           string
	Code                string
	RedirectURI         string
	ClientID            string
	ClientAssertion     string
	ClientAssertionType string
	Assertion           string // RFC 7523 jwt-bearer grant assertion (the DA JWT)
	SubjectToken        string
	SubjectTokenType    string
	ActorToken          string
	ActorTokenType      string
	Scope               string
	Resource            string
	RequestedActor      string // OBO: requested_actor
	CodeVerifier        string
}

// TokenResponse models the token endpoint response (RFC 6749 5.1).
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// AuthCode is the authorization code state stored by the AS (OBO
// flow).
type AuthCode struct {
	ClientID       string
	RequestedActor string // agentId
	Principal      Principal
	DA             string // principal-signed DA JWT obtained at consent
	VerifierHash   string // SHA-256 of the PKCE code_verifier
	ExpiresAt      time.Time
	Used           bool
}

// Issuer models the authorization server side: it validates
// principal-signed DA JWTs and issues outer AIC-JWTs (draft Section
// 10.2).
type Issuer struct {
	ID            string
	Key           crypto.Signer
	Kid           string
	Alg           string
	PrincipalJWKS map[string]crypto.PublicKey // kid -> principal public key
	Nonces        NonceStore
	Status        map[string]bool // jti -> revoked
	Codes         map[string]*AuthCode

	stateMu sync.Mutex // guards Status and Codes maps (F3)
}

// NewIssuer creates an issuer with fresh replay/status state.
func NewIssuer(id, kid string, key crypto.Signer, alg string, principalJWKS map[string]crypto.PublicKey) *Issuer {
	return &Issuer{
		ID:            id,
		Key:           key,
		Kid:           kid,
		Alg:           alg,
		PrincipalJWKS: principalJWKS,
		Nonces:        &memNonceStore{m: map[string]bool{}},
		Status:        map[string]bool{},
		Codes:         map[string]*AuthCode{},
	}
}

// IssuerKeys returns the issuer's public key under its kid.
func (is *Issuer) IssuerKeys() map[string]crypto.PublicKey {
	return map[string]crypto.PublicKey{is.Kid: is.Key.Public()}
}

// StatusCheckerFor returns a StatusChecker bound to the issuer status
// map (Token Status List simulation).
func (is *Issuer) StatusCheckerFor() StatusChecker {
	return func(ref StatusRef) error {
		is.stateMu.Lock()
		revoked := is.Status[ref.URI]
		is.stateMu.Unlock()
		if revoked {
			return fmt.Errorf("token revoked (status list %s idx %d)", ref.URI, ref.Idx)
		}
		return nil
	}
}

// Revoke marks a token identifier as revoked.
func (is *Issuer) Revoke(jti string) {
	is.stateMu.Lock()
	is.Status[jti] = true
	is.stateMu.Unlock()
}

// IssueFromDA implements the RFC 7523 assertion-style issuance: the
// Agent presents the principal-signed DA JWT, the AS validates it and
// wraps it in an outer AIC-JWT (draft Section 10.2).
func (is *Issuer) IssueFromDA(daToken string, agentPub crypto.PublicKey, aud []string, now time.Time) (string, *OuterClaims, error) {
	opts := VerifyOptions{
		Now:           now,
		PrincipalJWKS: is.PrincipalJWKS,
		NonceStore:    is.Nonces,
	}
	da, err := ValidateDA(daToken, opts)
	if err != nil {
		return "", nil, fmt.Errorf("token endpoint: DA validation failed: %w", err)
	}
	if !da.Aud.Contains(is.ID) {
		return "", nil, fmt.Errorf("token endpoint: DA aud %v does not include this AS %q", da.Aud, is.ID)
	}
	agentThumb, err := KeyHashOf(agentPub, "jkt")
	if err != nil {
		return "", nil, err
	}
	iat := now.Unix()
	outer := OuterClaims{
		Iss: is.ID,
		Sub: da.OAuthSubject(),
		Aud: Audience(aud),
		Iat: iat,
		Exp: da.Exp,
		Jti: da.Jti,
		Cnf: &Cnf{Jkt: agentThumb},
		Aic: &AICClaims{
			Ver:            1,
			Principal:      da.Principal,
			DelegationMode: da.DelegationMode,
			Capabilities:   da.Capabilities,
			Constraints:    da.Constraints,
		},
		Da: daToken,
	}
	if da.DelegationMode == ModeRepresentative {
		outer.Act = &Actor{Sub: da.AgentID}
	}
	tok, err := is.signOuter(&outer)
	if err != nil {
		return "", nil, err
	}
	return tok, &outer, nil
}

// IssueLightweight implements the lightweight consumer profile (draft
// Section 10.3): authorized mode only, no DA JWT.
func (is *Issuer) IssueLightweight(agentID string, agentPub crypto.PublicKey, principal Principal,
	caps []Capability, constraints []Capability, lifetime int64, aud []string, now time.Time) (string, *OuterClaims, error) {
	if lifetime < 1 || lifetime > MaxLifetime {
		return "", nil, fmt.Errorf("lightweight lifetime out of range")
	}
	agentThumb, err := KeyHashOf(agentPub, "jkt")
	if err != nil {
		return "", nil, err
	}
	jti, err := randomID(16)
	if err != nil {
		return "", nil, err
	}
	iat := now.Unix()
	outer := OuterClaims{
		Iss: is.ID,
		Sub: agentID,
		Aud: Audience(aud),
		Iat: iat,
		Exp: iat + lifetime,
		Jti: jti,
		Cnf: &Cnf{Jkt: agentThumb},
		Aic: &AICClaims{
			Ver:            1,
			Principal:      principal,
			DelegationMode: ModeAuthorized,
			Capabilities:   caps,
			Constraints:    constraints,
		},
	}
	tok, err := is.signOuter(&outer)
	if err != nil {
		return "", nil, err
	}
	return tok, &outer, nil
}

// HandleTokenRequest is the token endpoint entry point.  It
// dispatches by grant_type to the supported flows.
func (is *Issuer) HandleTokenRequest(req TokenRequest, agentPub crypto.PublicKey, aud []string, now time.Time) (TokenResponse, error) {
	switch req.GrantType {
	case GrantTypeJWTBearer:
		grant := req.Assertion
		if grant == "" {
			// Backward-compatible fallback: a DA supplied in the legacy
			// client_assertion field is treated as the grant assertion.
			grant = req.ClientAssertion
		}
		if grant == "" || req.ClientAssertionType != AssertionTypeJWT {
			return TokenResponse{}, fmt.Errorf("invalid_request: jwt-bearer assertion with type jwt-bearer required")
		}
		// Client authentication by client_assertion (RFC 7523 Section 2.2)
		// is distinct from the grant assertion.  When both are present, the
		// client assertion MUST be an authorized-mode AIC-JWT (Section 10.2).
		if req.Assertion != "" && req.ClientAssertion != "" {
			if err := is.verifyClientAssertion(req.ClientAssertion, req.ClientID, now); err != nil {
				return TokenResponse{}, err
			}
		}
		tok, outer, err := is.IssueFromDA(grant, agentPub, aud, now)
		if err != nil {
			return TokenResponse{}, err
		}
		return TokenResponse{AccessToken: tok, TokenType: TokenTypeBearer, ExpiresIn: outer.Exp - outer.Iat}, nil
	case GrantTypeAuthCode:
		return is.ExchangeCode(req, agentPub, aud, now)
	case GrantTypeTokenExchange:
		return is.TokenExchange(req, agentPub, aud, now)
	default:
		return TokenResponse{}, fmt.Errorf("unsupported_grant_type: %q", req.GrantType)
	}
}

// verifyClientAssertion validates an RFC 7523 client_assertion used for
// client authentication.  Per Section 10.2 the client assertion MUST be
// an authorized-mode AIC-JWT whose subject is the OAuth client_id of
// the agent; a representative-mode token has the resource owner as sub
// and MUST NOT be used in this slot.
func (is *Issuer) verifyClientAssertion(assertion, clientID string, now time.Time) error {
	payload, err := parseOuterPayload(assertion)
	if err != nil {
		return fmt.Errorf("invalid_client: %w", err)
	}
	if payload.Aic == nil || payload.Aic.DelegationMode != ModeAuthorized {
		return fmt.Errorf("invalid_client: client assertion must be an authorized-mode AIC-JWT")
	}
	if clientID != "" && payload.Sub != clientID {
		return fmt.Errorf("invalid_client: client assertion sub %q != client_id %q", payload.Sub, clientID)
	}
	if _, err := Validate(assertion, VerifyOptions{
		Now:            now,
		ExpectedIssuer: is.ID,
		IssuerKeys:     is.IssuerKeys(),
		PrincipalJWKS:  is.PrincipalJWKS,
	}); err != nil {
		return fmt.Errorf("invalid_client: %w", err)
	}
	return nil
}

func (is *Issuer) signOuter(o *OuterClaims) (string, error) {
	pb, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	hb, err := json.Marshal(map[string]any{"alg": is.Alg, "typ": TypOuter, "kid": is.Kid})
	if err != nil {
		return "", err
	}
	return SignCompact(hb, pb, is.Alg, is.Key)
}

// NewAuthCode simulates the OBO consent step: the principal consents
// and signs a DA for the requested actor; the AS stores an auth code
// bound to that actor (draft Section 10.2, OBO-style flow).
func (is *Issuer) NewAuthCode(clientID, requestedActor string, principal Principal, daToken, verifier string, ttl time.Duration, now time.Time) (string, error) {
	code, err := randomID(16)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	is.stateMu.Lock()
	is.Codes[code] = &AuthCode{
		ClientID:       clientID,
		RequestedActor: requestedActor,
		Principal:      principal,
		DA:             daToken,
		VerifierHash:   hex.EncodeToString(sum[:]),
		ExpiresAt:      now.Add(ttl),
	}
	is.stateMu.Unlock()
	return code, nil
}

// ExchangeCode implements the authorization code + PKCE exchange and
// issues the AIC-JWT for the requested actor (OBO).
func (is *Issuer) ExchangeCode(req TokenRequest, agentPub crypto.PublicKey, aud []string, now time.Time) (TokenResponse, error) {
	is.stateMu.Lock()
	code, ok := is.Codes[req.Code]
	if !ok || code.Used || now.After(code.ExpiresAt) {
		is.stateMu.Unlock()
		return TokenResponse{}, fmt.Errorf("invalid_grant: authorization code invalid or expired")
	}
	if code.ClientID != req.ClientID {
		is.stateMu.Unlock()
		return TokenResponse{}, fmt.Errorf("invalid_grant: code bound to different client")
	}
	if req.CodeVerifier == "" {
		is.stateMu.Unlock()
		return TokenResponse{}, fmt.Errorf("invalid_request: code_verifier required (PKCE)")
	}
	sum := sha256.Sum256([]byte(req.CodeVerifier))
	if hex.EncodeToString(sum[:]) != code.VerifierHash {
		is.stateMu.Unlock()
		return TokenResponse{}, fmt.Errorf("invalid_grant: PKCE verification failed")
	}
	code.Used = true
	// Snapshot the fields needed after unlocking (IssueFromDA performs
	// cryptographic work and must not hold the state lock).
	da := code.DA
	requestedActor := code.RequestedActor
	is.stateMu.Unlock()
	if req.ActorToken != "" {
		// OBO: the agent must authenticate with its own token
		if err := is.verifyAgentActor(req.ActorToken, requestedActor, now); err != nil {
			return TokenResponse{}, err
		}
	}
	tok, outer, err := is.IssueFromDA(da, agentPub, aud, now)
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: tok, TokenType: TokenTypeBearer, ExpiresIn: outer.Exp - outer.Iat}, nil
}

func (is *Issuer) verifyAgentActor(actorToken, expectedSub string, now time.Time) error {
	hb, pb, _, err := ParseCompact(actorToken)
	if err != nil {
		return fmt.Errorf("invalid_actor_token: %w", err)
	}
	var hdr Header
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return err
	}
	if err := checkHeader(hdr, TypOuter); err != nil {
		return err
	}
	key, ok := is.IssuerKeys()[hdr.Kid]
	if !ok {
		return fmt.Errorf("invalid_actor_token: unknown kid")
	}
	if err := VerifyCompact(actorToken, hdr.Alg, key); err != nil {
		return fmt.Errorf("invalid_actor_token: %w", err)
	}
	var outer OuterClaims
	if err := json.Unmarshal(pb, &outer); err != nil {
		return err
	}
	if outer.Sub != expectedSub {
		return fmt.Errorf("invalid_actor_token: sub %q != requested_actor %q", outer.Sub, expectedSub)
	}
	// L4: the actor token must be issued by this AS.
	if outer.Iss != is.ID {
		return fmt.Errorf("invalid_actor_token: issuer %q != %q", outer.Iss, is.ID)
	}
	// L4: the actor token must be targeted at this AS (OBO token endpoint).
	if !outer.Aud.Contains(is.ID) {
		return fmt.Errorf("invalid_actor_token: audience %v does not include %q", outer.Aud, is.ID)
	}
	// L2/L4: expiry + not-before (nbf represented by iat) enforcement.
	if outer.Exp != 0 && time.Unix(outer.Exp, 0).Before(now) {
		return fmt.Errorf("invalid_actor_token: token expired (exp=%d)", outer.Exp)
	}
	if outer.Iat != 0 && time.Unix(outer.Iat, 0).After(now.Add(time.Minute)) {
		return fmt.Errorf("invalid_actor_token: token not yet valid (iat=%d)", outer.Iat)
	}
	return nil
}

// PrincipalTokenClaims is the simulated subject credential used as the
// RFC 8693 subject_token (the principal's own access token).
type PrincipalTokenClaims struct {
	Iss    string       `json:"iss"`
	Sub    string       `json:"sub"`
	Aud    Audience     `json:"aud"`
	Iat    int64        `json:"iat"`
	Exp    int64        `json:"exp"`
	Jti    string       `json:"jti"`
	Grants []Capability `json:"grants"`
}

// NewPrincipalToken issues the principal's own access token.
func (is *Issuer) NewPrincipalToken(principalID string, grants []Capability, aud []string, lifetime int64, now time.Time) (string, error) {
	jti, err := randomID(16)
	if err != nil {
		return "", err
	}
	iat := now.Unix()
	claims := PrincipalTokenClaims{
		Iss: is.ID, Sub: principalID, Aud: Audience(aud),
		Iat: iat, Exp: iat + lifetime, Jti: jti, Grants: grants,
	}
	pb, _ := json.Marshal(claims)
	hb, _ := json.Marshal(map[string]any{"alg": is.Alg, "typ": "at+jwt", "kid": is.Kid})
	return SignCompact(hb, pb, is.Alg, is.Key)
}

// TokenExchange implements the RFC 8693 delegation scenario: the
// subject_token is the principal's credential, the actor_token is the
// Agent's AIC-JWT.  The issued token carries the intersection of the
// actor's capabilities and the subject's grants (draft Section 10.4).
func (is *Issuer) TokenExchange(req TokenRequest, agentPub crypto.PublicKey, aud []string, now time.Time) (TokenResponse, error) {
	if req.GrantType != GrantTypeTokenExchange {
		return TokenResponse{}, fmt.Errorf("unsupported_grant_type")
	}
	if req.SubjectToken == "" || req.ActorToken == "" {
		return TokenResponse{}, fmt.Errorf("invalid_request: subject_token and actor_token required")
	}
	// Validate the subject (principal) token.
	subject, err := is.verifyPrincipalToken(req.SubjectToken, now)
	if err != nil {
		return TokenResponse{}, err
	}
	// Reject a representative-mode token in the actor slot before deep
	// validation: its `sub` is the resource owner, so it is not an actor
	// credential.  (The subsequent Validate call would reject it anyway
	// without PA material; this gives the reason in its semantics.)
	actorPayload0, err := parseOuterPayload(req.ActorToken)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("invalid_actor_token: %w", err)
	}
	if actorPayload0.Aic.DelegationMode == ModeRepresentative {
		return TokenResponse{}, fmt.Errorf("invalid_actor_token: representative-mode token is not an actor credential")
	}
	// Validate the actor (Agent) AIC-JWT.
	actor, err := Validate(req.ActorToken, VerifyOptions{
		Now:            now,
		ExpectedIssuer: is.ID,
		IssuerKeys:     is.IssuerKeys(),
		PrincipalJWKS:  is.PrincipalJWKS,
	})
	if err != nil {
		return TokenResponse{}, fmt.Errorf("invalid_actor_token: %w", err)
	}
	// Intersection: keep the actor capabilities that are within the
	// subject grants (P_grants AND C_agent).
	var intersect []Capability
	for _, c := range actor.Capabilities {
		if capabilitySubset(c, subject.Grants) {
			intersect = append(intersect, c)
		}
	}
	if len(intersect) == 0 {
		return TokenResponse{}, fmt.Errorf("insufficient_scope: no overlapping capabilities")
	}
	// The principal binding and DA JWT are carried by the actor token.
	actorClaims, err := parseOuterPayload(req.ActorToken)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("invalid_actor_token: %w", err)
	}
	if actorClaims.Aic.DelegationMode == ModeRepresentative {
		// A representative-mode token has the resource owner as `sub` and
		// is not an actor credential; the actor_token slot is for the
		// agent's own (authorized-mode) AIC-JWT.
		return TokenResponse{}, fmt.Errorf("invalid_actor_token: representative-mode token is not an actor credential")
	}
	iat := now.Unix()
	exp := iat + 3600
	agentThumb, err := KeyHashOf(agentPub, "jkt")
	if err != nil {
		return TokenResponse{}, err
	}
	jti, err := randomID(16)
	if err != nil {
		return TokenResponse{}, err
	}
	outer := OuterClaims{
		Iss: is.ID,
		Sub: actorClaims.Sub,
		Aud: Audience(aud),
		Iat: iat,
		Exp: exp,
		Jti: jti,
		Cnf: &Cnf{Jkt: agentThumb},
		Aic: &AICClaims{
			Ver:            1,
			Principal:      actorClaims.Aic.Principal,
			DelegationMode: actorClaims.Aic.DelegationMode,
			Capabilities:   intersect,
		},
		Da: actorClaims.Da,
	}
	tok, err := is.signOuter(&outer)
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: tok, TokenType: TokenTypeBearer, ExpiresIn: 3600}, nil
}

func parseOuterPayload(actorToken string) (*OuterClaims, error) {
	_, pb, _, err := ParseCompact(actorToken)
	if err != nil {
		return nil, err
	}
	var outer OuterClaims
	if err := json.Unmarshal(pb, &outer); err != nil {
		return nil, err
	}
	if outer.Aic == nil {
		return nil, fmt.Errorf("actor token has no aic claim")
	}
	return &outer, nil
}

func (is *Issuer) verifyPrincipalToken(tok string, now time.Time) (*PrincipalTokenClaims, error) {
	hb, pb, _, err := ParseCompact(tok)
	if err != nil {
		return nil, fmt.Errorf("invalid_subject_token: %w", err)
	}
	var hdr Header
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, err
	}
	key, ok := is.IssuerKeys()[hdr.Kid]
	if !ok {
		return nil, fmt.Errorf("invalid_subject_token: unknown kid")
	}
	if err := VerifyCompact(tok, hdr.Alg, key); err != nil {
		return nil, fmt.Errorf("invalid_subject_token: %w", err)
	}
	var c PrincipalTokenClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, err
	}
	// L4: subject token must be issued by this AS (iss).
	if c.Iss != is.ID {
		return nil, fmt.Errorf("invalid_subject_token: issuer %q != %q", c.Iss, is.ID)
	}
	// L4: subject token must be targeted at this AS (aud).
	if !c.Aud.Contains(is.ID) {
		return nil, fmt.Errorf("invalid_subject_token: audience %v does not include %q", c.Aud, is.ID)
	}
	// L1/L4: the subject token must not be expired, and must not be used
	// before it is valid (nbf represented by iat).
	if c.Exp != 0 && time.Unix(c.Exp, 0).Before(now) {
		return nil, fmt.Errorf("invalid_subject_token: token expired (exp=%d)", c.Exp)
	}
	if c.Iat != 0 && time.Unix(c.Iat, 0).After(now.Add(time.Minute)) {
		return nil, fmt.Errorf("invalid_subject_token: token not yet valid (iat=%d)", c.Iat)
	}
	return &c, nil
}

// DPoPClaims is an RFC 9449 proof token payload (minimal).
type DPoPClaims struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Ath string `json:"ath,omitempty"`
}

// BuildDPoP creates an RFC 9449 proof JWT bound to an access token.
func BuildDPoP(key crypto.Signer, alg string, htm, htu, accessToken string, now time.Time) (string, DPoPClaims, error) {
	pub := key.Public()
	jwk, err := PublicKeyToJWK(pub)
	if err != nil {
		return "", DPoPClaims{}, err
	}
	sum := sha256.Sum256([]byte(accessToken))
	ath := b64uEncode(sum[:])
	jti, err := randomID(16)
	if err != nil {
		return "", DPoPClaims{}, err
	}
	claims := DPoPClaims{Htm: htm, Htu: htu, Jti: jti, Iat: now.Unix(), Ath: ath}
	pb, _ := json.Marshal(claims)
	hb, _ := json.Marshal(map[string]any{"alg": alg, "typ": "dpop+jwt", "jwk": jwk})
	tok, err := SignCompact(hb, pb, alg, key)
	if err != nil {
		return "", DPoPClaims{}, err
	}
	return tok, claims, nil
}

// VerifyDPoP validates an RFC 9449 proof against the access token and
// request, and returns the proof public key for the cnf check.
func VerifyDPoP(proof, accessToken, htm, htu string, now time.Time, replay NonceStore) (crypto.PublicKey, error) {
	hb, pb, _, err := ParseCompact(proof)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	var hdr Header
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("dpop: header malformed")
	}
	if hdr.JWK == nil {
		return nil, fmt.Errorf("dpop: header jwk required")
	}
	// L5: explicit algorithm allowlist; do not rely on the signature
	// switch alone to reject an unexpected alg.
	if !ImplementedAlgs[hdr.Alg] {
		return nil, fmt.Errorf("dpop: unsupported alg %q", hdr.Alg)
	}
	pub, err := JWKToPublic(*hdr.JWK)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	if err := VerifyCompact(proof, hdr.Alg, pub); err != nil {
		return nil, fmt.Errorf("dpop: signature invalid: %w", err)
	}
	var c DPoPClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, fmt.Errorf("dpop: payload malformed")
	}
	if c.Htm != htm {
		return nil, fmt.Errorf("dpop: htm mismatch")
	}
	if c.Htu != htu {
		return nil, fmt.Errorf("dpop: htu mismatch")
	}
	if c.Ath != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if b64uEncode(sum[:]) != c.Ath {
			return nil, fmt.Errorf("dpop: ath mismatch")
		}
	}
	if now.Sub(time.Unix(c.Iat, 0)) > 5*time.Minute || time.Unix(c.Iat, 0).Sub(now) > 5*time.Minute {
		return nil, fmt.Errorf("dpop: iat outside freshness window")
	}
	if replay != nil {
		if err := replay.CheckAndAdd(c.Jti); err != nil {
			return nil, fmt.Errorf("dpop: proof replay: %w", err)
		}
	}
	return pub, nil
}

// ResourceServer models the relying party / policy enforcement point.
type ResourceServer struct {
	ID                string
	IssuerID          string
	IssuerKeys        map[string]crypto.PublicKey
	PrincipalJWKS     map[string]crypto.PublicKey
	PrincipalMaterial *PrincipalKeyMaterial
	CapabilityPlugins map[string]CapabilityPlugin
	StatusChecker     StatusChecker
	ConstraintStrict  bool
	RejectDepthGT1    bool
	NonceStore        NonceStore
	PA                *PAClaims
}

// HTTPRequest captures the inputs a resource server sees.
type HTTPRequest struct {
	Method      string
	URL         string
	Audience    string
	AuthzHeader string // "Bearer <token>"
	DPoPHeader  string // optional DPoP proof JWT
	RequestCap  *Capability
	Context     RequestContext
}

// Check evaluates an HTTP request against an AIC-JWT and returns the
// decision (draft Section 11 + OAuth RS semantics).
func (rs *ResourceServer) Check(req HTTPRequest, now time.Time) (*Decision, error) {
	token, ok := strings.CutPrefix(req.AuthzHeader, "Bearer ")
	if !ok || token == "" {
		return nil, fmt.Errorf("invalid_request: missing bearer token")
	}
	var presenter crypto.PublicKey
	if req.DPoPHeader != "" {
		pub, err := VerifyDPoP(req.DPoPHeader, token, req.Method, req.URL, now, rs.NonceStore)
		if err != nil {
			return nil, fmt.Errorf("invalid_dpop_proof: %w", err)
		}
		presenter = pub
	}
	opts := VerifyOptions{
		Now:               now,
		ExpectedIssuer:    rs.IssuerID,
		ExpectedAudience:  []string{req.Audience},
		IssuerKeys:        rs.IssuerKeys,
		PrincipalJWKS:     rs.PrincipalJWKS,
		PrincipalMaterial: rs.PrincipalMaterial,
		PresenterKey:      presenter,
		RequestCapability: req.RequestCap,
		RequestContext:    req.Context,
		ConstraintStrict:  rs.ConstraintStrict,
		CapabilityPlugins: rs.CapabilityPlugins,
		StatusChecker:     rs.StatusChecker,
		// The RS does not treat the DA nonce as single-use: the primary
		// replay defence is the issuer-side nonce uniqueness check.
		// rs.NonceStore is used for DPoP proof jti replay only.
		RejectDepthGT1: rs.RejectDepthGT1,
		PA:             rs.PA,
	}
	dec, err := Validate(token, opts)
	if err != nil {
		return nil, fmt.Errorf("invalid_token: %w", err)
	}
	return dec, nil
}

// BearerToken extracts the access token from an Authorization header.
func BearerToken(authz string) string {
	tok, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok {
		return ""
	}
	return tok
}

type memNonceStore struct {
	mu sync.Mutex
	m  map[string]bool
}

func (s *memNonceStore) CheckAndAdd(nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[nonce] {
		return fmt.Errorf("reused nonce")
	}
	s.m[nonce] = true
	return nil
}

// NewMemNonceStore returns a process-local nonce/replay store.
func NewMemNonceStore() NonceStore {
	return &memNonceStore{m: map[string]bool{}}
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NormalizeURL is a small helper mirroring how an RS canonicalizes the
// request URI for DPoP htu comparison.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
