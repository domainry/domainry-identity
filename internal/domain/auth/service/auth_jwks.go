package service

import (
	"encoding/base64"
	"sort"
	"strings"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func (s *AuthDomainService) JSONWebKeySet() authmodel.JSONWebKeySet {
	keys := make([]authmodel.JSONWebKey, 0, len(s.verificationKeys))
	for kid, key := range s.verificationKeys {
		keys = append(keys, authmodel.JSONWebKey{
			KeyType: "OKP", Use: "sig", Algorithm: "EdDSA", KeyID: kid,
			Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(key),
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	return authmodel.JSONWebKeySet{Keys: keys}
}

func (s *AuthDomainService) OpenIDConfiguration() authmodel.OpenIDConfiguration {
	issuer := strings.TrimRight(s.issuer, "/")
	return authmodel.OpenIDConfiguration{
		Issuer: issuer, JWKSURI: issuer + "/.well-known/jwks.json",
		AuthorizationEndpoint: issuer + "/oauth2/authorize", TokenEndpoint: issuer + "/oauth2/token",
		ResponseTypesSupported: []string{"code"}, SubjectTypesSupported: []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"EdDSA"},
	}
}
