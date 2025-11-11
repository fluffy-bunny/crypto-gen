package jwt

import (
	"crypto_gen/internal/jwt/contracts"
	"strings"
	"testing"
	"time"

	golang_jwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
)

const jsonRS256Keys = `[{
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA3D1fBVtNHA1hitECH48y9cck1wYfbvwbBn63xP5iHmzqM3tH\nl8kQy5Aj8iUfKggRzppfSZVs1xrF0cvKt6AjcBTfSBr+KdQf4QzD2+MsXbFEYD5i\ntvaxjb15vkEcnrtHY7wIMKMrYHJ+ylCkOIXQtzEbneyHT3uklU1UQeBzDSxhmSxQ\nLDS/oJgAPWvJBAhNlhmpaJWG/IOW/C0Vs4vtm4lGOffV2Y8br5KAZ7CEn58M9YEa\nmzgxw+l9AqMkJOF1xXA52p3wB9Tb6Wouq1dDFNmepgWd2N1xfYeiB70CEVgn/9HV\n3PCgtGizJEMcNNseuFoNPMSLwhIQz0fA+zNshwIDAQABAoIBAAaeZ8RsVVfN0Ahp\n9kYmwKwzkl8xQ7EELbAwDyuQMY3Nal1RRLMXvWBdMiWUJcxIdrCJRVxGUR3xXLOw\nRN3L3uhUESRvKXWYy/R3tKFfT/Vapj3ZxaxdFSXUOs33YE9CPLJWZWmAyIUpSClM\nzx8UoRqyEuW7b5LrRI8wG4cFhcwUKfoNKRoiO/yw7lXR5CTGxEgdsKRP8nzi8s5w\n18W4AR9+6P9css8V36foa58BuWHPit1V0rSAIUo+geoau4KWvH/NQhrciv7UPiiJ\nAnPt8m/k4bH51K/J+5+1pEHp245XZVuFBB3LsW4yUH+JP3bs+B9IG+RbS8xhZPl+\niuN6k5ECgYEA4/v+klMfgp1JrOpYIyhhM+eP12pJwOXidVmFsIPJWGySUIY7+9PG\n9Yi682sTyOYDHY0rcf/1cv5lw/DQeFgg5rZdo+UD+lqQBKq/UicMpAmjEmiRf5Cv\nKFHaUJoGjSP9XTv5gxX+o4T+cWcvRHyR97ai+zTenstdZzqqvHJYgbMCgYEA902+\ncg+lCWRpHLGVxo4CaPDNXk/nWu96YUKD7T6T6YDgMVdffKOwdE/KLkrbl6bFpIqW\npIVJcdVXKbmOPKe/m9BAlNiiENoNOd6ezceCuW+HkDrqZjlVgAhcTWnp9+QLt7Ky\nciBdzGoN2lLutkdDeG1k26sN98ApcCitqbhaN90CgYEAobmu2unwXl1pWCpdH4OT\ngJhxZ2RUsWvh+1DoD1FNUVajbE/s2TVf2+mEhQyeWlMgPqRX/2SNH2frlNWNbPFH\nVaJkRtE8wynfJBBj68kbpHnZnkNjg1SFjFqUPb0ljJXNM4hJ9X1yx1iejp+d3j1n\n5os+jmjwy0CEH6h0WX3b3xUCgYA38S04jhNuOXmRlRZlcPBYnshGIlsadfvADpTb\nUQGSm6WbY8Fk535eAUKiECr2djJVU0hadRA1IOZzuNbVH7k3XPeO9CZNG5ZMVfCk\nahJHMlR/KuSlNSkDKmD+3gugGMURy+mT6YBuYjs5/PKk5x/7GPvsuRgSyDRXe8w1\nDU/TPQKBgQCecczRnFXq6tZ0Z8OEXPTZbkLekWuhoUEenaVYL27VYLS7U9gT5RxS\noGp/shIHW4/KK7kkfZlh0r0iksr6ERIY6OJRbMVWun4nYjIwM7DbgJ6Ny6HPKXh7\nAdwWvHsXrAUQTzUfkdCx52v3KMAnBEUZvwJ7GgSU1dYOwqjdcNq71g==\n-----END RSA PRIVATE KEY-----\n",
    "public_key": "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA3D1fBVtNHA1hitECH48y9cck1wYfbvwbBn63xP5iHmzqM3tHl8kQ\ny5Aj8iUfKggRzppfSZVs1xrF0cvKt6AjcBTfSBr+KdQf4QzD2+MsXbFEYD5itvax\njb15vkEcnrtHY7wIMKMrYHJ+ylCkOIXQtzEbneyHT3uklU1UQeBzDSxhmSxQLDS/\noJgAPWvJBAhNlhmpaJWG/IOW/C0Vs4vtm4lGOffV2Y8br5KAZ7CEn58M9YEamzgx\nw+l9AqMkJOF1xXA52p3wB9Tb6Wouq1dDFNmepgWd2N1xfYeiB70CEVgn/9HV3PCg\ntGizJEMcNNseuFoNPMSLwhIQz0fA+zNshwIDAQAB\n-----END RSA PUBLIC KEY-----\n",
    "not_before": "2025-11-11T20:01:38Z",
    "not_after": "2026-11-11T20:01:38Z",
    "password": "",
    "kid": "dca382365fbe4d55ac6b997392406b8a",
    "public_jwk": {
        "alg": "RS256",
        "e": "AQAB",
        "kid": "dca382365fbe4d55ac6b997392406b8a",
        "kty": "RSA",
        "n": "3D1fBVtNHA1hitECH48y9cck1wYfbvwbBn63xP5iHmzqM3tHl8kQy5Aj8iUfKggRzppfSZVs1xrF0cvKt6AjcBTfSBr-KdQf4QzD2-MsXbFEYD5itvaxjb15vkEcnrtHY7wIMKMrYHJ-ylCkOIXQtzEbneyHT3uklU1UQeBzDSxhmSxQLDS_oJgAPWvJBAhNlhmpaJWG_IOW_C0Vs4vtm4lGOffV2Y8br5KAZ7CEn58M9YEamzgxw-l9AqMkJOF1xXA52p3wB9Tb6Wouq1dDFNmepgWd2N1xfYeiB70CEVgn_9HV3PCgtGizJEMcNNseuFoNPMSLwhIQz0fA-zNshw",
        "use": "sig"
    },
    "private_jwk": {
        "alg": "RS256",
        "d": "Bp5nxGxVV83QCGn2RibArDOSXzFDsQQtsDAPK5Axjc1qXVFEsxe9YF0yJZQlzEh2sIlFXEZRHfFcs7BE3cve6FQRJG8pdZjL9He0oV9P9VqmPdnFrF0VJdQ6zfdgT0I8slZlaYDIhSlIKUzPHxShGrIS5btvkutEjzAbhwWFzBQp-g0pGiI7_LDuVdHkJMbESB2wpE_yfOLyznDXxbgBH37o_1yyzxXfp-hrnwG5Yc-K3VXStIAhSj6B6hq7gpa8f81CGtyK_tQ-KIkCc-3yb-ThsfnUr8n7n7WkQenbjldlW4UEHcuxbjJQf4k_duz4H0gb5FtLzGFk-X6K43qTkQ",
        "dp": "obmu2unwXl1pWCpdH4OTgJhxZ2RUsWvh-1DoD1FNUVajbE_s2TVf2-mEhQyeWlMgPqRX_2SNH2frlNWNbPFHVaJkRtE8wynfJBBj68kbpHnZnkNjg1SFjFqUPb0ljJXNM4hJ9X1yx1iejp-d3j1n5os-jmjwy0CEH6h0WX3b3xU",
        "dq": "N_EtOI4Tbjl5kZUWZXDwWJ7IRiJbGnX7wA6U21EBkpulm2PBZOd-XgFCohAq9nYyVVNIWnUQNSDmc7jW1R-5N1z3jvQmTRuWTFXwpGoSRzJUfyrkpTUpAypg_t4LoBjFEcvpk-mAbmI7OfzypOcf-xj77LkYEsg0V3vMNQ1P0z0",
        "e": "AQAB",
        "kid": "dca382365fbe4d55ac6b997392406b8a",
        "kty": "RSA",
        "n": "3D1fBVtNHA1hitECH48y9cck1wYfbvwbBn63xP5iHmzqM3tHl8kQy5Aj8iUfKggRzppfSZVs1xrF0cvKt6AjcBTfSBr-KdQf4QzD2-MsXbFEYD5itvaxjb15vkEcnrtHY7wIMKMrYHJ-ylCkOIXQtzEbneyHT3uklU1UQeBzDSxhmSxQLDS_oJgAPWvJBAhNlhmpaJWG_IOW_C0Vs4vtm4lGOffV2Y8br5KAZ7CEn58M9YEamzgxw-l9AqMkJOF1xXA52p3wB9Tb6Wouq1dDFNmepgWd2N1xfYeiB70CEVgn_9HV3PCgtGizJEMcNNseuFoNPMSLwhIQz0fA-zNshw",
        "p": "4_v-klMfgp1JrOpYIyhhM-eP12pJwOXidVmFsIPJWGySUIY7-9PG9Yi682sTyOYDHY0rcf_1cv5lw_DQeFgg5rZdo-UD-lqQBKq_UicMpAmjEmiRf5CvKFHaUJoGjSP9XTv5gxX-o4T-cWcvRHyR97ai-zTenstdZzqqvHJYgbM",
        "q": "902-cg-lCWRpHLGVxo4CaPDNXk_nWu96YUKD7T6T6YDgMVdffKOwdE_KLkrbl6bFpIqWpIVJcdVXKbmOPKe_m9BAlNiiENoNOd6ezceCuW-HkDrqZjlVgAhcTWnp9-QLt7KyciBdzGoN2lLutkdDeG1k26sN98ApcCitqbhaN90",
        "qi": "nnHM0ZxV6urWdGfDhFz02W5C3pFroaFBHp2lWC9u1WC0u1PYE-UcUqBqf7ISB1uPyiu5JH2ZYdK9IpLK-hESGOjiUWzFVrp-J2IyMDOw24Cejcuhzyl4ewHcFrx7F6wFEE81H5HQsedr9yjAJwRFGb8CexoElNXWDsKo3XDau9Y",
        "use": "sig"
    }
}]`

const jsonES256Keys = `[{
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
	keys, err := LoadSigningKey([]byte(jsonES256Keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "0b2cd2e54c924ce89f010f242862367d", keys[0].Kid)
}
func TestCreateKeySet(t *testing.T) {
	keys, err := LoadSigningKey([]byte(jsonES256Keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "0b2cd2e54c924ce89f010f242862367d", keys[0].Kid)
	keySet, err := CreateKeySet(keys)
	require.NoError(t, err)
	keyLen := keySet.Len()
	require.Equal(t, keyLen, 1)
	keyS, ok := keySet.Key(0)
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
	keys, err := LoadSigningKey([]byte(jsonES256Keys))
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

func TestMintJWTWithRS256Keys(t *testing.T) {
	// Load RS256 signing keys
	keys, err := LoadSigningKey([]byte(jsonRS256Keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "dca382365fbe4d55ac6b997392406b8a", keys[0].Kid)
	require.Equal(t, "RS256", keys[0].PrivateJwk.Alg)

	// Prepare standard claims
	now := time.Now()
	standardClaims := &golang_jwt.StandardClaims{
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Issuer:    "https://test-issuer.com",
		Audience:  "https://test-audience.com",
		Subject:   "test-subject-123",
	}

	// Prepare custom claims
	extraClaims := contracts.NewClaims()
	extraClaims.Set("scope", "read write")
	extraClaims.Set("roles", []string{"admin", "user"})
	extraClaims.Set("custom_data", map[string]interface{}{
		"department": "engineering",
		"level":      "senior",
	})

	// Mint the JWT
	token, err := MintStandardJWT(keys[0], standardClaims, extraClaims)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Verify the token has the expected structure (header.payload.signature)
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "JWT should have 3 parts separated by dots")

	// Create key set for validation
	keySet, err := CreateKeySet(keys)
	require.NoError(t, err)

	// Validate the minted token
	validator, err := NewJWTValidator(&JWTValidatorOptions{
		KeySet:            keySet,
		RequiredIssuer:    stringPtr("https://test-issuer.com"),
		ValidateSignature: boolPtr(true),
		ClockSkewMinutes:  5,
	})
	require.NoError(t, err)

	vToken, err := validator.ParseTokenRaw(token)
	require.NoError(t, err)
	require.NotNil(t, vToken)

	// Verify standard claims
	require.Equal(t, standardClaims.Issuer, vToken.Issuer())
	require.Equal(t, standardClaims.Subject, vToken.Subject())
	require.Equal(t, standardClaims.IssuedAt, vToken.IssuedAt().Unix())
	require.Equal(t, standardClaims.NotBefore, vToken.NotBefore().Unix())
	require.Equal(t, standardClaims.ExpiresAt, vToken.Expiration().Unix())
	require.Contains(t, vToken.Audience(), "https://test-audience.com")

	// Verify custom claims
	privateClaims := vToken.PrivateClaims()

	scope, ok := privateClaims["scope"]
	require.True(t, ok)
	require.Equal(t, "read write", scope)

	roles, ok := privateClaims["roles"]
	require.True(t, ok)
	roleSlice, ok := roles.([]interface{})
	require.True(t, ok)
	require.Len(t, roleSlice, 2)
	require.Contains(t, roleSlice, "admin")
	require.Contains(t, roleSlice, "user")

	customData, ok := privateClaims["custom_data"]
	require.True(t, ok)
	customDataMap, ok := customData.(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "engineering", customDataMap["department"])
	require.Equal(t, "senior", customDataMap["level"])
}

func TestMintGenericJWTWithRS256(t *testing.T) {
	// Load RS256 signing keys
	keys, err := LoadSigningKey([]byte(jsonRS256Keys))
	require.NoError(t, err)

	// Create generic claims
	claims := contracts.NewClaims()
	claims.Set("iss", "https://generic-issuer.com")
	claims.Set("sub", "generic-subject")
	claims.Set("aud", "https://generic-audience.com")
	claims.Set("exp", time.Now().Add(time.Hour).Unix())
	claims.Set("iat", time.Now().Unix())
	claims.Set("nbf", time.Now().Unix())
	claims.Set("jti", "unique-jwt-id-123")
	claims.Set("custom_claim", "custom_value")

	// Mint JWT using generic function
	token, err := MintGenericJWT(keys[0], claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Parse and validate the token structure
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	// Create key set and validator
	keySet, err := CreateKeySet(keys)
	require.NoError(t, err)

	validator, err := NewJWTValidator(&JWTValidatorOptions{
		KeySet:            keySet,
		RequiredIssuer:    stringPtr("https://generic-issuer.com"),
		ValidateSignature: boolPtr(true),
		ClockSkewMinutes:  5,
	})
	require.NoError(t, err)

	// Validate the token
	vToken, err := validator.ParseTokenRaw(token)
	require.NoError(t, err)

	// Verify claims
	require.Equal(t, "https://generic-issuer.com", vToken.Issuer())
	require.Equal(t, "generic-subject", vToken.Subject())
	require.Contains(t, vToken.Audience(), "https://generic-audience.com")

	// Check standard JWT ID claim using the dedicated method
	require.Equal(t, "unique-jwt-id-123", vToken.JwtID())

	privateClaims := vToken.PrivateClaims()
	customClaim, ok := privateClaims["custom_claim"]
	require.True(t, ok, "custom_claim should exist in private claims")
	require.Equal(t, "custom_value", customClaim)
}

func TestRS256KeyStructure(t *testing.T) {
	keys, err := LoadSigningKey([]byte(jsonRS256Keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)

	key := keys[0]

	// Verify key properties
	require.Equal(t, "dca382365fbe4d55ac6b997392406b8a", key.Kid)
	require.NotEmpty(t, key.PrivateKey)
	require.NotEmpty(t, key.PublicKey)
	require.Empty(t, key.Password) // No password in test data

	// Verify private JWK structure for RSA
	require.Equal(t, "RS256", key.PrivateJwk.Alg)
	require.Equal(t, "RSA", key.PrivateJwk.Kty)
	require.Equal(t, "sig", key.PrivateJwk.Use)
	require.Equal(t, key.Kid, key.PrivateJwk.Kid)
	require.Equal(t, "AQAB", key.PrivateJwk.E)
	require.NotEmpty(t, key.PrivateJwk.N)
	require.NotEmpty(t, key.PrivateJwk.D)

	// Verify public JWK structure for RSA
	require.Equal(t, "RS256", key.PublicJwk.Alg)
	require.Equal(t, "RSA", key.PublicJwk.Kty)
	require.Equal(t, "sig", key.PublicJwk.Use)
	require.Equal(t, key.Kid, key.PublicJwk.Kid)
	require.Equal(t, "AQAB", key.PublicJwk.E)
	require.NotEmpty(t, key.PublicJwk.N)
	// Public key should not have private components (D field not in PublicJwk struct)

	// Verify keys can be used to create JWT tokens
	claims := contracts.NewClaims()
	claims.Set("test", "value")
	claims.Set("iat", time.Now().Unix())
	claims.Set("exp", time.Now().Add(time.Hour).Unix())

	token, err := MintGenericJWT(key, claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)
}

func TestRS256JWTHeaderValidation(t *testing.T) {
	keys, err := LoadSigningKey([]byte(jsonRS256Keys))
	require.NoError(t, err)

	// Create simple claims
	claims := contracts.NewClaims()
	claims.Set("iss", "test-issuer")
	claims.Set("sub", "test-subject")
	claims.Set("aud", "test-audience")
	claims.Set("exp", time.Now().Add(time.Hour).Unix())
	claims.Set("iat", time.Now().Unix())

	// Mint token
	token, err := MintGenericJWT(keys[0], claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Verify token structure
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "JWT should have header.payload.signature format")

	// Create key set for validation (this tests that the token can be validated)
	keySet, err := CreateKeySet(keys)
	require.NoError(t, err)

	// Validate using the validator (which tests signature and structure)
	validator, err := NewJWTValidator(&JWTValidatorOptions{
		KeySet:            keySet,
		RequiredIssuer:    stringPtr("test-issuer"),
		ValidateSignature: boolPtr(true),
		ClockSkewMinutes:  5,
	})
	require.NoError(t, err)

	validatedToken, err := validator.ParseTokenRaw(token)
	require.NoError(t, err)
	require.NotNil(t, validatedToken)

	// Verify claims were properly set
	require.Equal(t, "test-issuer", validatedToken.Issuer())
	require.Equal(t, "test-subject", validatedToken.Subject())
	require.Contains(t, validatedToken.Audience(), "test-audience")
}
