package service

import authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
)

// AuthRepository is the persistence boundary actually consumed by AuthDomainService.
// Identity governance uses its own repository; auth must not receive that
// aggregate's full storage contract merely because Store implements both.
// AuthDomainService owns authentication sessions and credential operations.
type AuthDomainService struct {
	identity          authcontract.AuthIdentityPort
	localeIdentity    authcontract.AuthLocaleIdentityPort
	authorization     authcontract.AuthAuthorization
	identityStore     authrepository.AuthRepository
	secret            []byte
	issuer            string
	audience          string
	activeKID         string
	activePrivateKey  ed25519.PrivateKey
	verificationKeys  map[string]ed25519.PublicKey
	defaultPassword   string
	accessTTL         time.Duration
	refreshTTL        time.Duration
	maxLoginFailures  int
	loginLockDuration time.Duration
	otpResendCooldown time.Duration
	otpMaxAttempts    int
	passwordPolicy    authpolicy.AuthPasswordPolicy
	defaultLocale     string
	normalizeLocale   func(string) string
	supportedLocales  map[string]struct{}
	readRandomBytes   func([]byte) (int, error)
	guestMu           sync.Mutex
	challengeMu       sync.Mutex
	challenges        map[string]authmodel.AuthProviderChallenge
}

func NewAuthDomainService(identity authcontract.AuthIdentityPort, identityStore authrepository.AuthRepository, secret string, defaultPassword string, accessTTL time.Duration, refreshTTL time.Duration, maxLoginFailures int, loginLockDuration time.Duration, otpResendCooldown time.Duration, otpMaxAttempts int, passwordPolicy authpolicy.AuthPasswordPolicy) *AuthDomainService {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		secret = "dev-generated-auth-secret-change-me"
	}
	defaultPassword = strings.TrimSpace(defaultPassword)
	if defaultPassword == "" {
		defaultPassword = "Domainry@2026"
	}
	if accessTTL <= 0 {
		accessTTL = 15 * time.Minute
	}
	if refreshTTL <= 0 {
		refreshTTL = 7 * 24 * time.Hour
	}
	if maxLoginFailures <= 0 {
		maxLoginFailures = 5
	}
	if loginLockDuration <= 0 {
		loginLockDuration = 15 * time.Minute
	}
	if otpResendCooldown <= 0 {
		otpResendCooldown = 60 * time.Second
	}
	if otpMaxAttempts <= 0 {
		otpMaxAttempts = 5
	}
	if passwordPolicy.MinLength <= 0 {
		passwordPolicy.MinLength = 8
	}
	service := &AuthDomainService{
		identity:          identity,
		authorization:     identity,
		identityStore:     identityStore,
		secret:            []byte(secret),
		issuer:            "http://localhost:8081",
		audience:          "domainry-runtime",
		defaultPassword:   defaultPassword,
		accessTTL:         accessTTL,
		refreshTTL:        refreshTTL,
		maxLoginFailures:  maxLoginFailures,
		loginLockDuration: loginLockDuration,
		otpResendCooldown: otpResendCooldown,
		otpMaxAttempts:    otpMaxAttempts,
		passwordPolicy:    passwordPolicy,
		defaultLocale:     "en-US",
		supportedLocales:  map[string]struct{}{"en-US": {}},
		readRandomBytes:   rand.Read,
		challenges:        map[string]authmodel.AuthProviderChallenge{},
	}
	_ = service.ConfigureSigningKeys("dev-v1", secret, nil)
	service.localeIdentity, _ = identity.(authcontract.AuthLocaleIdentityPort)
	return service
}

// ConfigureLocalePolicy binds Auth projections to the Runtime catalog without
// making the Auth domain depend on a concrete localization adapter.
func (s *AuthDomainService) ConfigureLocalePolicy(defaultLocale string, normalize func(string) string, supported []string) {
	defaultLocale = strings.TrimSpace(defaultLocale)
	if defaultLocale == "" {
		defaultLocale = "en-US"
	}
	allowed := make(map[string]struct{}, len(supported)+1)
	for _, locale := range supported {
		if locale = strings.TrimSpace(locale); locale != "" {
			allowed[locale] = struct{}{}
		}
	}
	allowed[defaultLocale] = struct{}{}
	s.defaultLocale, s.normalizeLocale, s.supportedLocales = defaultLocale, normalize, allowed
}

// ConfigureSigningKeys derives deterministic Ed25519 keys from configured
// secrets. Production can use ConfigureTokenAuthority to
// supply explicit private/public key material.
func (s *AuthDomainService) ConfigureSigningKeys(activeKID, activeSecret string, verification map[string]string) error {
	activeKID, activeSecret = strings.TrimSpace(activeKID), strings.TrimSpace(activeSecret)
	if activeKID == "" || activeSecret == "" {
		return fmt.Errorf("active JWT kid and secret are required")
	}
	seed := sha256.Sum256([]byte(activeSecret))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	keys := make(map[string]ed25519.PublicKey, len(verification)+1)
	keys[activeKID] = append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	for kid, secret := range verification {
		kid, secret = strings.TrimSpace(kid), strings.TrimSpace(secret)
		if kid == "" || secret == "" || kid == activeKID {
			return fmt.Errorf("JWT verification keys require unique non-empty kid and secret")
		}
		verificationSeed := sha256.Sum256([]byte(secret))
		verificationPrivate := ed25519.NewKeyFromSeed(verificationSeed[:])
		keys[kid] = append(ed25519.PublicKey(nil), verificationPrivate.Public().(ed25519.PublicKey)...)
	}
	s.activeKID, s.secret, s.activePrivateKey, s.verificationKeys = activeKID, []byte(activeSecret), privateKey, keys
	return nil
}

func (s *AuthDomainService) ConfigureTokenMetadata(issuer, audience string) error {
	issuer, audience = strings.TrimRight(strings.TrimSpace(issuer), "/"), strings.TrimSpace(audience)
	if issuer == "" || audience == "" {
		return fmt.Errorf("JWT issuer and audience are required")
	}
	s.issuer, s.audience = issuer, audience
	return nil
}

// ConfigureTokenAuthority configures the stable token contract used by both
// the in-process module and remote SaaS binding. Keys use raw URL-safe base64.
func (s *AuthDomainService) ConfigureTokenAuthority(issuer, audience, activeKID, privateKey string, verification map[string]string) error {
	issuer, audience, activeKID = strings.TrimSpace(issuer), strings.TrimSpace(audience), strings.TrimSpace(activeKID)
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil || issuer == "" || audience == "" || activeKID == "" || len(decoded) != ed25519.PrivateKeySize {
		return fmt.Errorf("issuer, audience, kid and a raw Ed25519 private key are required")
	}
	keys := make(map[string]ed25519.PublicKey, len(verification)+1)
	active := append(ed25519.PrivateKey(nil), decoded...)
	keys[activeKID] = append(ed25519.PublicKey(nil), active.Public().(ed25519.PublicKey)...)
	for kid, encoded := range verification {
		kid = strings.TrimSpace(kid)
		public, decodeErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
		if decodeErr != nil || kid == "" || kid == activeKID || len(public) != ed25519.PublicKeySize {
			return fmt.Errorf("verification keys require unique kid and raw Ed25519 public key")
		}
		keys[kid] = append(ed25519.PublicKey(nil), public...)
	}
	s.issuer, s.audience, s.activeKID, s.activePrivateKey, s.verificationKeys = issuer, audience, activeKID, active, keys
	return nil
}
