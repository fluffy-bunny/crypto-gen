package rs256

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"crypto_gen/cmd/cli/cmd/ecdsa/shared"
	"crypto_gen/cmd/cli/cmd/rs256/rotation"
	"crypto_gen/internal/cobra_utils"
	rsautil "crypto_gen/internal/rsautil"
	"crypto_gen/internal/utils"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/square/go-jose"
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

var command = &cobra.Command{
	Use:   "rs256",
	Short: "generate rs256 keys",
	Long: `
Docker examples
-------------------------------------------------------
docker run ghstahl/crypto-gen rs256
` +
		`docker run ghstahl/crypto-gen rs256 --time_not_before="2006-01-02T15:04:05Z" --time_not_after="2007-01-02T15:04:05Z" --password="Tricycle2-Hazing-Illusion"
`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := cobra_utils.ParentPersistentPreRunE(cmd, args); err != nil {
			return err
		}
		if utils.IsEmptyOrNil(timeNotBeforeValue) {
			shared.TimeNotBefore = time.Now().UTC()
			return nil
		}
		parser, err := parsetime.NewParseTime()
		if err != nil {
			return err
		}
		parsed, err := parser.Parse(timeNotBeforeValue)
		if err != nil {
			return err
		}
		shared.TimeNotBefore = parsed.UTC()
		return nil
	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if utils.IsEmptyOrNil(timeNotAfterValue) {
			shared.TimeNotAfter = shared.AddMonth(shared.TimeNotBefore, 12)
			return nil
		}
		parser, err := parsetime.NewParseTime()
		if err != nil {
			return err
		}
		parsed, err := parser.Parse(timeNotAfterValue)
		if err != nil {
			return err
		}
		shared.TimeNotAfter = parsed.UTC()
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		privateKey, privateEncoded, publicEncoded, err := rsautil.GenerateRSAPublicPrivateKeySet(shared.Password)
		if err != nil {
			return err
		}
		kid := strings.ReplaceAll(uuid.New().String(), "-", "")
		publicKey := &privateKey.PublicKey

		priv := jose.JSONWebKey{Key: privateKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
		privJS, err := priv.MarshalJSON()
		if err != nil {
			return err
		}
		var mapPrivateJWK map[string]interface{}
		if err := json.Unmarshal(privJS, &mapPrivateJWK); err != nil {
			return err
		}

		pub := jose.JSONWebKey{Key: publicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
		pubJS, err := pub.MarshalJSON()
		if err != nil {
			return err
		}
		var mapPublicJWK map[string]interface{}
		if err := json.Unmarshal(pubJS, &mapPublicJWK); err != nil {
			return err
		}

		keySet := shared.KeySet{
			KID:        kid,
			Password:   shared.Password,
			PrivateKey: privateEncoded,
			PublicKey:  publicEncoded,
			NotBefore:  shared.TimeNotBefore.Format(time.RFC3339),
			NotAfter:   shared.TimeNotAfter.Format(time.RFC3339),
			PublicJWK:  mapPublicJWK,
			PrivateJWK: mapPrivateJWK,
		}
		fmt.Println(utils.PrettyJSON(keySet))
		return nil
	},
}

func InitCommand(parent *cobra.Command) {
	parent.AddCommand(command)

	command.PersistentFlags().StringVar(&timeNotBeforeValue, timeNotBeforeFlagName, "", fmt.Sprintf("i.e. --%s=\"2006-01-02T15:04:05Z\"", timeNotBeforeFlagName))
	viper.BindPFlag(timeNotBeforeValue, command.PersistentFlags().Lookup(timeNotBeforeFlagName))

	command.Flags().StringVar(&timeNotAfterValue, timeNotAfterFlagName, "", fmt.Sprintf("i.e. --%s=\"2006-01-02T15:04:05Z\"", timeNotAfterFlagName))
	viper.BindPFlag(timeNotAfterValue, command.Flags().Lookup(timeNotAfterFlagName))

	command.PersistentFlags().StringVar(&shared.Password, passwordFlagName, "", fmt.Sprintf("i.e. --%s=\"Tricycle2-Hazing-Illusion\"", passwordFlagName))
	command.MarkFlagRequired(passwordFlagName)
	viper.BindPFlag(shared.Password, command.PersistentFlags().Lookup(passwordFlagName))

	rotation.InitCommand(command)
}
