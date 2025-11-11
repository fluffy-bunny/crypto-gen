package models

import "time"

type (
	 struct {
		Alg string `json:"alg"`
		Crv string `json:"crv,omitempty"` // For EC keys
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Use string `json:"use"`
		X PublicJwk  string `json:"x,omitempty"` // For EC keys
		Y   string `json:"y,omitempty"` // For EC keys
		E   string `json:"e,omitempty"` // For RSA keys
		N   string `json:"n,omitempty"` // For RSA keys
	}
	PrivateJwk struct {
		Alg string `json:"alg"`
		Crv string `json:"crv,omitempty"` // For EC keys
		D   string `json:"d"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Use string `json:"use"`
		X   string `json:"x,omitempty"`  // For EC keys
		Y   string `json:"y,omitempty"`  // For EC keys
		E   string `json:"e,omitempty"`  // For RSA keys
		N   string `json:"n,omitempty"`  // For RSA keys
		P   string `json:"p,omitempty"`  // For RSA keys
		Q   string `json:"q,omitempty"`  // For RSA keys
		Dp  string `json:"dp,omitempty"` // For RSA keys
		Dq  string `json:"dq,omitempty"` // For RSA keys
		Qi  string `json:"qi,omitempty"` // For RSA keys
	}
	SigningKey struct {
		PrivateKey string     `json:"private_key"`
		PublicKey  string     `json:"public_key"`
		NotBefore  time.Time  `json:"not_before"`
		NotAfter   time.Time  `json:"not_after"`
		Password   string     `json:"password"`
		Kid        string     `json:"kid"`
		PublicJwk  PublicJwk  `json:"public_jwk"`
		PrivateJwk PrivateJwk `json:"private_jwk"`
	}
)
