package rsautil

import (
	"reflect"
	"testing"

	golang_jwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
)

const (
	testPassword = "secret"
)

func TestGenerateRSAPublicPrivateKeySet(t *testing.T) {
	privateKey, privateEncoded, publicEncoded, err := GenerateRSAPublicPrivateKeySet(testPassword)
	require.NoError(t, err)
	require.NotEmpty(t, privateEncoded)
	require.NotEmpty(t, publicEncoded)

	priv2, pub2, err := decode(testPassword, privateEncoded, publicEncoded)
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(privateKey, priv2))
	require.True(t, reflect.DeepEqual(&privateKey.PublicKey, pub2))
}

func TestRS256Sign(t *testing.T) {
	_, privateEncoded, publicEncoded, err := GenerateRSAPublicPrivateKeySet(testPassword)
	require.NoError(t, err)

	privateKey, publicKey, err := decode(testPassword, privateEncoded, publicEncoded)
	require.NoError(t, err)

	claims := golang_jwt.MapClaims{
		"sub": "tester",
	}

	token := golang_jwt.NewWithClaims(golang_jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test"

	signed, err := token.SignedString(privateKey)
	require.NoError(t, err)

	parsed, err := golang_jwt.Parse(signed, func(token *golang_jwt.Token) (interface{}, error) {
		require.Equal(t, golang_jwt.SigningMethodRS256, token.Method)
		return publicKey, nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
}

func TestDecodePrivatePem(t *testing.T) {
	generated, privateEncoded, _, err := GenerateRSAPublicPrivateKeySet(testPassword)
	require.NoError(t, err)

	priv, pub, err := decodePrivatePem(testPassword, privateEncoded)
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(generated, priv))
	require.True(t, reflect.DeepEqual(&generated.PublicKey, pub))
}

func BenchmarkGenerateRSAPublicPrivateKeySet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _, err := GenerateRSAPublicPrivateKeySet(testPassword)
		if err != nil {
			b.Fatal(err)
		}
	}
}
