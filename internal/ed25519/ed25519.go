package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

type (
	KeyPair struct {
		PrivateKey string    `json:"private_key"`
		PublicKey  string    `json:"public_key"`
		NotBefore  time.Time `json:"not_before"`
		NotAfter   time.Time `json:"not_after"`
		Kid        string    `json:"kid"`
		PublicJWK  JWK       `json:"public_jwk"`
		PrivateJWK JWK       `json:"private_jwk"`
	}
	JWK struct {
		Alg string `json:"alg"`
		Crv string `json:"crv"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Use string `json:"use"`
		X   string `json:"x"`
		D   string `json:"d,omitempty"` // Private key component
	}
)

func GenerateED25519KeyPair() (*KeyPair, error) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	// Create a random KID (simplified version)
	kidBytes := make([]byte, 16)
	if _, err := rand.Read(kidBytes); err != nil {
		return nil, fmt.Errorf("failed to generate kid: %v", err)
	}
	kid := fmt.Sprintf("%x", kidBytes)

	// Convert keys to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Create JWK representation
	publicJWK := JWK{
		Alg: "EdDSA",
		Crv: "Ed25519",
		Kid: kid,
		Kty: "OKP",
		Use: "sig",
		X:   base64.RawURLEncoding.EncodeToString(publicKey),
	}

	privateJWK := JWK{
		Alg: "EdDSA",
		Crv: "Ed25519",
		Kid: kid,
		Kty: "OKP",
		Use: "sig",
		X:   base64.RawURLEncoding.EncodeToString(publicKey),
		D:   base64.RawURLEncoding.EncodeToString(privateKey.Seed()),
	}

	// Create key pair structure
	keyPair := &KeyPair{
		PrivateKey: string(privateKeyPEM),
		PublicKey:  string(publicKeyPEM),
		NotBefore:  time.Now(),
		NotAfter:   time.Now().AddDate(1, 0, 0), // 1 year validity
		Kid:        kid,
		PublicJWK:  publicJWK,
		PrivateJWK: privateJWK,
	}

	return keyPair, nil
}

func ParseKeys(jsonKeys string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	var keyPair KeyPair
	if err := json.Unmarshal([]byte(jsonKeys), &keyPair); err != nil {
		return nil, nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Parse private key
	block, _ := pem.Decode([]byte(keyPair.PrivateKey))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	edPrivKey, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an Ed25519 private key")
	}

	// Parse public key
	block, _ = pem.Decode([]byte(keyPair.PublicKey))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	edPubKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an Ed25519 public key")
	}

	return edPubKey, edPrivKey, nil
}
