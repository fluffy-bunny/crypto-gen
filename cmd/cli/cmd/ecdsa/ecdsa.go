/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package ecdsa

import (
	"fmt"
	"strings"
	"time"

	"crypto_gen/cmd/cli/cmd/ecdsa/shared"
	"crypto_gen/internal/cobra_utils"
	"crypto_gen/internal/ecdsa"
	"crypto_gen/internal/utils"

	"crypto_gen/cmd/cli/cmd/ecdsa/rotation"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tkuchiki/parsetime"
)

const (
	timeNotBeforeFlagName = "time_not_before"
	timeNotAfterFlagName  = "time_not_after"
	passwordFlagName      = "password"
)

var (
	timeNotBeforeValue string

	timeNotAfterValue string
)

// aboutCmd represents the about command
var command = &cobra.Command{
	Use:   "ecdsa",
	Short: "generate ecdsa keys",
	Long: `
docker run ghstahl/crypto-gen version

Generate a single ECDSA key
-------------------------------------------------------
docker run ghstahl/crypto-gen ecdsa 
docker run ghstahl/crypto-gen ecdsa --time_not_before="2006-01-02T15:04:05Z" --time_not_after="2007-01-02T15:04:05Z" --password="Tricycle2-Hazing-Illusion"
docker run ghstahl/crypto-gen ecdsa --time_not_before="2006-01-02Z" --time_not_after="2007-01-02Z" --password="Tricycle2-Hazing-Illusion"

{
    "private_key": "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,94256fd7bcfa6a3e78262200b8cbd9ca\n\nxouwLPx0XF6b48haUc64HgSdCKV0Uo5qKZoiXUcf2QW1m12IofAOSR3reU5UYPop\nV8YITld40NSNKNzlmeEUPthJAkfDO6jGBG2mGlMg5HNFBwZBMDIOL0joCEf3qgBX\nDUlUmm0LBFdFq9wDsBLPdDfzsmmFqrl3YCoIdW11wpU=\n-----END EC PRIVATE KEY-----\n",
    "public_key": "-----BEGIN EC  PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs1PHWA8LHErGe0RZC0YC8Jr5apxi\naFbxZ7AlrELr3ts1xWQBZMVSJ6y7TM1U3DPo96FhUSaMqY3bas8h3DLlgw==\n-----END EC  PUBLIC KEY-----\n",
    "not_before": "2006-01-02T00:00:00Z",
    "not_after": "0001-01-01T00:00:00Z"
}
`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		err := cobra_utils.ParentPersistentPreRunE(cmd, args)
		if err != nil {
			return err
		}
		if utils.IsEmptyOrNil(timeNotBeforeValue) {
			shared.TimeNotBefore = time.Now().UTC()
		} else {
			p, err := parsetime.NewParseTime()
			if err != nil {
				return err
			}

			t, err := p.Parse(timeNotBeforeValue)
			if err != nil {
				return err
			}
			shared.TimeNotBefore = t.UTC()
		}
		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		_, privateEncoded, publicEncoded, err := ecdsa.GenerateECDSAPublicPrivateKeySet(shared.Password)
		if err != nil {
			return err
		}
		kid := strings.ReplaceAll(uuid.New().String(), "-", "")
		keySet := shared.EcdsaKeySet{
			KID:        kid,
			Password:   shared.Password,
			PrivateKey: privateEncoded,
			PublicKey:  publicEncoded,
			NotBefore:  shared.TimeNotBefore.Format(time.RFC3339),
			NotAfter:   shared.TimeNotAfter.Format(time.RFC3339),
		}
		fmt.Println(utils.PrettyJSON(keySet))
		return nil
	},
	PreRunE: func(cmd *cobra.Command, args []string) error {

		if utils.IsEmptyOrNil(timeNotAfterValue) {
			shared.TimeNotAfter = AddMonth(shared.TimeNotBefore, 12)
		} else {
			p, err := parsetime.NewParseTime()
			if err != nil {
				return err
			}

			t, err := p.Parse(timeNotBeforeValue)
			if err != nil {
				return err
			}
			shared.TimeNotBefore = t.UTC()
		}
		return nil
	},
}

func InitCommand(parent *cobra.Command) {
	parent.AddCommand(command)

	command.PersistentFlags().StringVar(&timeNotBeforeValue, timeNotBeforeFlagName, "", fmt.Sprintf("i.e. --%s=\"2006-01-02T15:04:05Z\" or --%s=\"2006-01-02T15:04:05\"", timeNotBeforeFlagName, timeNotBeforeFlagName))
	viper.BindPFlag(timeNotBeforeValue, command.PersistentFlags().Lookup(timeNotBeforeFlagName))

	command.Flags().StringVar(&timeNotAfterValue, timeNotAfterFlagName, "", fmt.Sprintf("i.e. --%s=\"2006-01-02T15:04:05Z\" or --%s=\"2006-01-02T15:04:05\"", timeNotAfterFlagName, timeNotAfterFlagName))
	viper.BindPFlag(timeNotAfterValue, command.Flags().Lookup(timeNotAfterFlagName))

	command.PersistentFlags().StringVar(&shared.Password, passwordFlagName, "", fmt.Sprintf("i.e. --%s=\"Tricycle2-Hazing-Illusion\"", passwordFlagName))
	command.MarkFlagRequired(passwordFlagName)
	viper.BindPFlag(shared.Password, command.PersistentFlags().Lookup(passwordFlagName))

	rotation.InitCommand(command)
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
