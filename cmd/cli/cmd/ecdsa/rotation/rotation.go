/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package rotation

import (
	"fmt"
	"time"

	"crypto_gen/cmd/cli/cmd/ecdsa/shared"
	"crypto_gen/internal/cobra_utils"
	"crypto_gen/internal/ecdsa"
	"crypto_gen/internal/utils"

	"github.com/spf13/cobra"
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
	Short: "generate ecdsa key rotation set",
	Long: `
Generate a ECDSA key rotation set
-------------------------------------------------------
docker run ghstahl/crypto-gen ecdsa rotation
docker run ghstahl/crypto-gen ecdsa rotation --time_not_before="2022-01-01Z" --password="Tricycle2-Hazing-Illusion"
docker run ghstahl/crypto-gen ecdsa rotation --time_not_before="2022-01-01Z" --password="Tricycle2-Hazing-Illusion" --key_duration_months=12 --overlap_months=1 --count=2

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
		_, privateEncoded, publicEncoded, err := ecdsa.GenerateECDSAPublicPrivateKeySet(shared.Password)
		if err != nil {
			return err
		}

		var keySets []shared.EcdsaKeySet
		currentNotBefore := shared.TimeNotBefore
		for i := 0; i < int(count); i++ {
			notBefore := currentNotBefore
			notAfter := AddMonth(notBefore, int(keyDurationMonths))
			keySets = append(keySets, shared.EcdsaKeySet{
				Password:   shared.Password,
				PrivateKey: privateEncoded,
				PublicKey:  publicEncoded,
				NotBefore:  notBefore.Format(time.RFC3339),
				NotAfter:   notAfter.Format(time.RFC3339),
			})
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
