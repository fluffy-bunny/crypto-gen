package jwt

import (
	"crypto_gen/internal/jwt/contracts"
	"testing"
	"time"

	golang_jwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
)

const jsonKeys = `[{
    "private_key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFA+8y3M5qxkjuI7HOUAPVgrsjUnu5kwRjsZlbCmyabCoAoGCCqGSM49\nAwEHoUQDQgAEYMrUm/S5+d+euQHrrzQMWJSFafSYcgUE0RYjfI7sErK75hSdE0aj\nPNMXaaDG395zD18VxjsmqPTWom17ncVnnw==\n-----END EC PRIVATE KEY-----\n",
    "public_key": "-----BEGIN EC  PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYMrUm/S5+d+euQHrrzQMWJSFafSY\ncgUE0RYjfI7sErK75hSdE0ajPNMXaaDG395zD18VxjsmqPTWom17ncVnnw==\n-----END EC  PUBLIC KEY-----\n",
    "not_before": "2022-01-02T00:00:00Z",
    "not_after": "2023-01-02T00:00:00Z",
    "password": "",
    "kid": "0b2cd2e54c924ce89f010f242862367d",
    "public_jwk": {
        "alg": "ES256",
        "crv": "P-256",
        "kid": "0b2cd2e54c924ce89f010f242862367d",
        "kty": "EC",
        "use": "sig",
        "x": "YMrUm_S5-d-euQHrrzQMWJSFafSYcgUE0RYjfI7sErI",
        "y": "u-YUnRNGozzTF2mgxt_ecw9fFcY7Jqj01qJte53FZ58"
    },
    "private_jwk": {
        "alg": "ES256",
        "crv": "P-256",
        "d": "UD7zLczmrGSO4jsc5QA9WCuyNSe7mTBGOxmVsKbJpsI",
        "kid": "0b2cd2e54c924ce89f010f242862367d",
        "kty": "EC",
        "use": "sig",
        "x": "YMrUm_S5-d-euQHrrzQMWJSFafSYcgUE0RYjfI7sErI",
        "y": "u-YUnRNGozzTF2mgxt_ecw9fFcY7Jqj01qJte53FZ58"
    }
}]`

func TestKeyUnmarshal(t *testing.T) {
	keys, err := LoadSigningKey([]byte(jsonKeys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "0b2cd2e54c924ce89f010f242862367d", keys[0].Kid)
}
func TestCreateKeySet(t *testing.T) {
	keys, err := LoadSigningKey([]byte(jsonKeys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "0b2cd2e54c924ce89f010f242862367d", keys[0].Kid)
	keySet, err := CreateKeySet(keys)
	require.NoError(t, err)
	keyLen := keySet.Len()
	require.Equal(t, keyLen, 1)
	keyS, ok := keySet.Get(0)
	require.True(t, ok)
	require.Equal(t, "0b2cd2e54c924ce89f010f242862367d", keyS.KeyID())
}
func stringPtr(s string) *string {
	return &s
}
func boolPtr(b bool) *bool {
	return &b
}
func TestJWTValidator(t *testing.T) {
	keys, err := LoadSigningKey([]byte(jsonKeys))
	require.NoError(t, err)
	keySet, err := CreateKeySet(keys)
	require.NoError(t, err)
	issuer := "https://example.com"

	now := time.Now()
	standardClaims := &golang_jwt.StandardClaims{
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Issuer:    "https://example.com",
		Audience:  "https://example.com",
		Subject:   "test",
	}
	extraClaims := contracts.NewClaims()
	extraClaims.Set("test", "test")
	token, err := MintStandardJWT(keys[0], standardClaims, extraClaims)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	validator, err := NewJWTValidator(&JWTValidatorOptions{
		KeySet:            keySet,
		RequiredIssuer:    stringPtr(issuer),
		ValidateSignature: boolPtr(true),
		ClockSkewMinutes:  5,
	})
	require.NoError(t, err)
	require.NotNil(t, validator)
	vToken, err := validator.ParseTokenRaw(token)
	require.NoError(t, err)
	require.NotNil(t, vToken)

	require.Equal(t, standardClaims.Issuer, vToken.Issuer())
	require.Equal(t, standardClaims.Audience, vToken.Audience()[0])
	require.Equal(t, standardClaims.IssuedAt, vToken.IssuedAt().Unix())
	privateClaims := vToken.PrivateClaims()
	v, ok := privateClaims["test"]
	require.True(t, ok)
	require.Equal(t, "test", v)
}
