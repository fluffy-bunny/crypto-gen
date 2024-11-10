/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package rotation

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"crypto_gen/cmd/cli/cmd/ecdsa/shared"
	"crypto_gen/internal/cobra_utils"
	internal_ed25519 "crypto_gen/internal/ed25519"
	"crypto_gen/internal/utils"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/square/go-jose"
)

const (
	keyDurationMonthsFlagName = "key_duration_months"
	overlapMonthsFlagName     = "overlap_months"
	countFlagName             = "count"
)

var (
	keyDurationMonths uint
	overlapMonths     uint
	count             uint
)

// aboutCmd represents the about command
var command = &cobra.Command{
	Use:   "rotation",
	Short: "generate ed25519 key rotation set",
	Long: `
Generate a ECDSA key rotation set
-------------------------------------------------------
docker run ghstahl/crypto-gen ed25519 rotation
docker run ghstahl/crypto-gen ed25519 rotation --time_not_before="2022-01-01Z" --password="Tricycle2-Hazing-Illusion"
docker run ghstahl/crypto-gen ed25519 rotation --time_not_before="2022-01-01Z" --password="Tricycle2-Hazing-Illusion" --key_duration_months=12 --overlap_months=1 --count=2

[
{
	"private_key": "-----BEGIN EC PRIVATE KEY-----\n**REDACTED**\n-----END EC PRIVATE KEY-----\n",
	"public_key": "-----BEGIN EC  PUBLIC KEY-----\n**REDACTED**\n-----END EC  PUBLIC KEY-----\n",
	"not_before": "2022-01-01T00:00:00Z",
	"not_after": "2023-01-01T00:00:00Z"
},
{
	"private_key": "-----BEGIN EC PRIVATE KEY-----\n**REDACTED**\n-----END EC PRIVATE KEY-----\n",
	"public_key": "-----BEGIN EC  PUBLIC KEY-----\n**REDACTED**\n-----END EC  PUBLIC KEY-----\n",
	"not_before": "2022-12-01T00:00:00Z",
	"not_after": "2023-12-01T00:00:00Z"
}
]	
	`,
	PersistentPreRunE: cobra_utils.ParentPersistentPreRunE,
	RunE: func(cmd *cobra.Command, args []string) error {

		var keySets []*internal_ed25519.KeyPair
		currentNotBefore := shared.TimeNotBefore
		for i := 0; i < int(count); i++ {
			kp, err := internal_ed25519.GenerateED25519KeyPair()
			if err != nil {
				return err
			}

			notBefore := currentNotBefore
			notAfter := AddMonth(notBefore, int(keyDurationMonths))
			kid := strings.ReplaceAll(uuid.New().String(), "-", "")
			publicKey := kp.PublicKey
			privateKey := kp.PrivateKey
			kp.NotBefore = notBefore
			kp.NotAfter = notAfter
			priv := jose.JSONWebKey{Key: privateKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
			privJS, err := priv.MarshalJSON()
			var mapPrivateJWK map[string]interface{}
			json.Unmarshal(privJS, &mapPrivateJWK)

			pub := jose.JSONWebKey{Key: publicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
			pubJS, err := pub.MarshalJSON()
			var mapPublicJWK map[string]interface{}
			json.Unmarshal(pubJS, &mapPublicJWK)
			keySets = append(keySets, kp)
			currentNotBefore = AddMonth(notAfter, int(0-overlapMonths))
		}

		fmt.Println(utils.PrettyJSON(keySets))
		return nil
	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if keyDurationMonths < 1 || keyDurationMonths > 12 {
			return fmt.Errorf("key_duration_months must be between 1 and 12")
		}
		if overlapMonths < 1 || overlapMonths > 3 {
			return fmt.Errorf("overlap_months must be between 1 and 3")
		}
		if count < 1 || count > 100 {
			return fmt.Errorf("count must be between 1 and 100")
		}
		if keyDurationMonths < overlapMonths {
			return fmt.Errorf("key_duration_months must be greater than overlap_months")
		}
		return nil
	},
}

func InitCommand(parent *cobra.Command) {
	parent.AddCommand(command)

	command.Flags().UintVar(&keyDurationMonths, keyDurationMonthsFlagName, 12, fmt.Sprintf("i.e. --%s=12", keyDurationMonthsFlagName))
	command.Flags().UintVar(&overlapMonths, overlapMonthsFlagName, 1, fmt.Sprintf("i.e. --%s=1", overlapMonthsFlagName))
	command.Flags().UintVar(&count, countFlagName, 10, fmt.Sprintf("i.e. --%s=10", countFlagName))
}

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
