package jwt

import (
	"encoding/json"

	jwtminter "github.com/fluffy-bunny/fluffycore/contracts/jwtminter"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
)

func LoadSigningKey(jsonKeys []byte) ([]*jwtminter.SigningKey, error) {
	keys := make([]*jwtminter.SigningKey, 0)
	err := json.Unmarshal([]byte(jsonKeys), &keys)
	if err != nil {
		return nil, err
	}
	return keys, nil
}
func CreateKeySet(keys []*jwtminter.SigningKey) (jwk.Set, error) {
	set := jwk.NewSet()
	for _, key := range keys {
		keyB, _ := json.Marshal(key.PrivateJwk)
		privkey, err := jwk.ParseKey(keyB)
		if err != nil {
			return nil, err
		}
		pubkey, err := jwk.PublicKeyOf(privkey)
		if err != nil {
			return nil, err
		}
		set.AddKey(pubkey)
	}
	return set, nil
}
