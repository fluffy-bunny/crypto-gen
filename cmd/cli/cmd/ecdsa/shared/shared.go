package shared

import "time"

var (
	TimeNotBefore time.Time

	TimeNotAfter time.Time

	Password string
)

type (
	EcdsaKeySet struct {
		PrivateKey string                 `json:"private_key"`
		PublicKey  string                 `json:"public_key"`
		NotBefore  string                 `json:"not_before"`
		NotAfter   string                 `json:"not_after"`
		Password   string                 `json:"password"`
		KID        string                 `json:"kid"`
		JWK        map[string]interface{} `json:"jwk"`
	}
)
