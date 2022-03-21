/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package ecdsa

import (
	"fmt"
	"time"

	"crypto_gen/cmd/cli/cmd/ecdsa/shared"
	"crypto_gen/internal/cobra_utils"
	"crypto_gen/internal/ecdsa"
	"crypto_gen/internal/utils"

	"crypto_gen/cmd/cli/cmd/ecdsa/rotation"

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
	Long:  ``,
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
		type ecdsaKeySet struct {
			PrivateKey string `json:"private_key"`
			PublicKey  string `json:"public_key"`
			NotBefore  string `json:"not_before"`
			NotAfter   string `json:"not_after"`
		}
		keySet := ecdsaKeySet{
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
