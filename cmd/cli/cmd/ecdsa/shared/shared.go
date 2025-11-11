package shared

import (
	"time"
)

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
		PublicJWK  map[string]interface{} `json:"public_jwk"`
		PrivateJWK map[string]interface{} `json:"private_jwk"`
	}
)

type KeySet = EcdsaKeySet

func AddMonth(t time.Time, offsetMonth int) time.Time {
	return t.AddDate(0, offsetMonth, 0)
}
func StartOfMonthUTC(offsetMonth int) time.Time {
	now := time.Now()
	currentYear := now.Year()
	nextYear := currentYear
	currentMonth := now.Month()
	tt := time.Date(nextYear, currentMonth, 1, 0, 0, 0, 0, time.UTC)
	tt = tt.AddDate(0, offsetMonth, 0)
	return tt
}
