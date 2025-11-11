package jwt

import (
	"crypto_gen/internal/jwt/contracts"
	"encoding/json"
	"fmt"
	"strings"

	jwtminter "github.com/fluffy-bunny/fluffycore/contracts/jwtminter"

	core_hashset "github.com/fluffy-bunny/fluffycore/gods/sets/hashset"
	fluffycore_utils "github.com/fluffy-bunny/fluffycore/utils"
	golang_jwt "github.com/golang-jwt/jwt"
	xid "github.com/rs/xid"
)

func MintStandardJWT(signingKey *jwtminter.SigningKey, standardClaims *golang_jwt.StandardClaims, claims contracts.IClaims) (string, error) {
	standardClaims.Id = xid.New().String()
	var buildClaimsMap = func(standardClaims *golang_jwt.StandardClaims, extras contracts.IClaims) contracts.IClaims {
		audienceSet := core_hashset.NewStringSet()
		if fluffycore_utils.IsNotEmptyOrNil(standardClaims.Audience) {
			audienceSet.Add(standardClaims.Audience)
		}
		if fluffycore_utils.IsNotEmptyOrNil(extras) {
			extraAudInterface := extras.Get("aud")
			switch tt := extraAudInterface.(type) {
			case string:
				audienceSet.Add(tt)
			case []string:
				audienceSet.Add(tt...)
			}
		}
		if audienceSet.Size() > 0 {
			extras.Set("aud", audienceSet.Values())
		}

		var standard map[string]interface{}
		standardJSON, _ := json.Marshal(standardClaims)
		json.Unmarshal(standardJSON, &standard)
		delete(standard, "aud")

		for k, v := range standard {
			extras.Set(k, v)
		}
		return extras
	}

	claims = buildClaimsMap(standardClaims, claims)
	token, err := MintGenericJWT(signingKey, claims)
	if err != nil {
		return "", err
	}
	return token, nil
}

func MintGenericJWT(signingKey *jwtminter.SigningKey, claims contracts.IClaims) (string, error) {
	var method golang_jwt.SigningMethod
	switch signingKey.PrivateJwk.Alg {
	case "RS256":
		method = golang_jwt.SigningMethodRS256
	case "RS384":
		method = golang_jwt.SigningMethodRS384
	case "RS512":
		method = golang_jwt.SigningMethodRS512
	case "ES256":
		method = golang_jwt.SigningMethodES256
	case "ES384":
		method = golang_jwt.SigningMethodES384
	case "ES512":
		method = golang_jwt.SigningMethodES512
	default:
		return "", fmt.Errorf("unsupported signing method: %s", signingKey.PrivateJwk.Alg)
	}
	kid := signingKey.Kid
	signedKey := []byte(signingKey.PrivateKey)

	var getKey = func() (interface{}, error) {
		var key interface{}
		if strings.HasPrefix(signingKey.PrivateJwk.Alg, "ES") {
			v, err := golang_jwt.ParseECPrivateKeyFromPEM(signedKey)
			if err != nil {
				return "", err
			}
			key = v
			return key, nil
		}

		v, err := golang_jwt.ParseRSAPrivateKeyFromPEM(signedKey)
		if err != nil {
			return "", err
		}
		key = v
		return key, nil
	}
	token := golang_jwt.NewWithClaims(method, claims.JwtClaims())
	token.Header["kid"] = kid
	key, err := getKey()
	if err != nil {
		return "", err
	}

	jwtToken, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return jwtToken, nil
}
