package ecdsa

import (
	"crypto/ecdsa"
	"fmt"
	"reflect"
	"testing"

	jwtPascal "github.com/pascaldekloe/jwt"
	jose "github.com/square/go-jose"
	"github.com/stretchr/testify/require"
)

const (
	password          = "secret"
	privateJsonWebKey = `{"use":"sig","kty":"EC","kid":"dog","crv":"P-256","alg":"ES256","x":"bR1WGN_P_XyQyRmD_09ZPE_yfdwZaojwjjunt5Nw_Zs","y":"WK13PPvIiK1WLN0Vf003PafERJCAUUVmpl5WwdH0N0A","d":"eTQKtWpamjuyHZfy2n_w0pBj6WLrHwpil2AVb5ZM2Is"}`
	publicJsonWebKeyh = `{"use":"sig","kty":"EC","kid":"dog","crv":"P-256","alg":"ES256","x":"bR1WGN_P_XyQyRmD_09ZPE_yfdwZaojwjjunt5Nw_Zs","y":"WK13PPvIiK1WLN0Vf003PafERJCAUUVmpl5WwdH0N0A"}`
)

func TestGenerateECDSAPublicPrivateKeySet(t *testing.T) {

	privateKey, privateEncoded, publicEncoded, err := GenerateECDSAPublicPrivateKeySet(password)
	require.NoError(t, err)

	fmt.Println(privateEncoded)
	fmt.Println(publicEncoded)

	publicKey := &privateKey.PublicKey
	//	priv2, pub2, err := decode(password, privateEncoded, publicEncoded)
	priv2, pub2, err := decodePrivatePem(password, privateEncoded)

	require.True(t, reflect.DeepEqual(privateKey, priv2))
	require.True(t, reflect.DeepEqual(publicKey, pub2))

	kid := "dog"
	priv := jose.JSONWebKey{Key: privateKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	privJS, err := priv.MarshalJSON()
	fmt.Println(string(privJS))

	pub := jose.JSONWebKey{Key: publicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	pubJS, err := pub.MarshalJSON()
	fmt.Println(string(pubJS))

	bytes := []byte(privJS)
	var jwk2 jose.JSONWebKey
	jwk2.UnmarshalJSON(bytes)
	privateKey2 := (jwk2.Key).(*ecdsa.PrivateKey)

	require.True(t, reflect.DeepEqual(privateKey, privateKey2))

	bytes = []byte(pubJS)
	var jwk3 jose.JSONWebKey
	jwk3.UnmarshalJSON(bytes)
	publicKey2 := (jwk3.Key).(*ecdsa.PublicKey)
	require.True(t, reflect.DeepEqual(publicKey, publicKey2))

}
func TestECDSASign(t *testing.T) {
	_, privateEncoded, publicEncoded, err := GenerateECDSAPublicPrivateKeySet(password)
	priv2, pub2, err := decode(password, privateEncoded, publicEncoded)

	const want = "sweet-44 tender-9 hot-juicy porkchops"

	var c jwtPascal.Claims
	c.KeyID = want
	token, err := c.ECDSASign("ES256", priv2)
	require.NoError(t, err)

	got, err := jwtPascal.ECDSACheck(token, pub2)
	require.NoError(t, err)

	require.Equal(t, want, got.KeyID)

}
func TestKeyRegister(t *testing.T) {

	_, privateEncoded, publicEncoded, _ := GenerateECDSAPublicPrivateKeySet(password)
	fmt.Println(privateEncoded)
	fmt.Println(publicEncoded)

	var keys jwtPascal.KeyRegister

	n, err := keys.LoadPEM([]byte(privateEncoded), []byte(password))
	require.NoError(t, err)
	require.Equal(t, 1, n)

}
