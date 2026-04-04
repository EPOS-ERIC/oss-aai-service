package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

const oidcSigningKeyMetaKey = "oidc_signing_key_pem"

type oidcSigner struct {
	privateKey *rsa.PrivateKey
	keyID      string
}

func newOIDCSigner(store *localStore) (*oidcSigner, error) {
	pemValue, err := loadOrCreateOIDCSigningKey(store)
	if err != nil {
		return nil, err
	}

	privateKey, err := parseOIDCPrivateKey([]byte(pemValue))
	if err != nil {
		return nil, err
	}

	return &oidcSigner{
		privateKey: privateKey,
		keyID:      oidcKeyID(&privateKey.PublicKey),
	}, nil
}

func loadOrCreateOIDCSigningKey(store *localStore) (string, error) {
	if value, ok, err := store.getAppMeta(oidcSigningKeyMetaKey); err != nil {
		return "", err
	} else if ok && value != "" {
		return value, nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("generate OIDC signing key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("marshal OIDC signing key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := store.setAppMeta(oidcSigningKeyMetaKey, string(pemBytes)); err != nil {
		return "", err
	}

	return string(pemBytes), nil
}

func parseOIDCPrivateKey(pemValue []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemValue)
	if block == nil {
		return nil, fmt.Errorf("decode OIDC signing key PEM")
	}

	if privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privateKey, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC signing key: %w", err)
	}

	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("OIDC signing key is not RSA")
	}

	return privateKey, nil
}

func (s *oidcSigner) signIDToken(claims map[string]any) (string, error) {
	header := map[string]string{
		"alg": "RS256",
		"kid": s.keyID,
		"typ": "JWT",
	}

	encodedHeader, err := encodeJWTPart(header)
	if err != nil {
		return "", err
	}
	encodedClaims, err := encodeJWTPart(claims)
	if err != nil {
		return "", err
	}

	signingInput := encodedHeader + "." + encodedClaims
	hash := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *oidcSigner) jwks() map[string]any {
	publicKey := &s.privateKey.PublicKey

	return map[string]any{
		"keys": []any{
			map[string]string{
				"alg": "RS256",
				"e":   base64.RawURLEncoding.EncodeToString(bigEndianBytes(publicKey.E)),
				"kid": s.keyID,
				"kty": "RSA",
				"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				"use": "sig",
			},
		},
	}
}

func oidcKeyID(publicKey *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "oidc-signing-key"
	}

	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:8])
}

func encodeJWTPart(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func bigEndianBytes(value int) []byte {
	if value == 0 {
		return []byte{0}
	}

	bytes := make([]byte, 0, 8)
	for value > 0 {
		bytes = append([]byte{byte(value & 0xff)}, bytes...)
		value >>= 8
	}

	return bytes
}
