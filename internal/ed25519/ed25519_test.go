package ed25519

import (
	"fmt"
	"testing"

	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/stretchr/testify/require"
)

func TestGenerateED25519(t *testing.T) {
	keyPair, err := GenerateED25519KeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPair)

	jsonKeys, err := json.MarshalIndent(keyPair, "", "    ")
	require.NoError(t, err)

	publicKey, privateKey, err := ParseKeys(string(jsonKeys))
	require.NoError(t, err)

	message := []byte("Hello, this is a test message to sign!")

	// Sign the message
	signature := ed25519.Sign(privateKey, message)
	valid := ed25519.Verify(publicKey, message, signature)
	require.True(t, valid)
}

func signAndVerify(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	// Message to sign
	message := []byte("Hello, this is a test message to sign!")

	// Sign the message
	signature := ed25519.Sign(privateKey, message)

	// Print the original message and signature
	fmt.Printf("Original Message: %s\n", string(message))
	fmt.Printf("Signature (base64): %s\n", base64.StdEncoding.EncodeToString(signature))

	// Verify the signature
	valid := ed25519.Verify(publicKey, message, signature)
	fmt.Printf("Signature Valid: %v\n", valid)
}
