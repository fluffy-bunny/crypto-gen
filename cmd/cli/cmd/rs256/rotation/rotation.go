package rotation

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"crypto_gen/cmd/cli/cmd/ecdsa/shared"
	"crypto_gen/internal/cobra_utils"
	rsautil "crypto_gen/internal/rsautil"
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

var command = &cobra.Command{
	Use:   "rotation",
	Short: "generate rs256 key rotation set",
	Long: `
Generate an RS256 key rotation set
-------------------------------------------------------
docker run ghstahl/crypto-gen rs256 rotation
` +
		`docker run ghstahl/crypto-gen rs256 rotation --time_not_before="2022-01-01Z" --password="Tricycle2-Hazing-Illusion"
` +
		`docker run ghstahl/crypto-gen rs256 rotation --time_not_before="2022-01-01Z" --password="Tricycle2-Hazing-Illusion" --key_duration_months=12 --overlap_months=1 --count=2
`,
	PersistentPreRunE: cobra_utils.ParentPersistentPreRunE,
	RunE: func(cmd *cobra.Command, args []string) error {
		var keySets []shared.KeySet
		currentNotBefore := shared.TimeNotBefore
		for i := 0; i < int(count); i++ {
			privateKey, privateEncoded, publicEncoded, err := rsautil.GenerateRSAPublicPrivateKeySet(shared.Password)
			if err != nil {
				return err
			}
			notBefore := currentNotBefore
			notAfter := shared.AddMonth(notBefore, int(keyDurationMonths))
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

			keySets = append(keySets, shared.KeySet{
				KID:        kid,
				Password:   shared.Password,
				PrivateKey: privateEncoded,
				PublicKey:  publicEncoded,
				NotBefore:  notBefore.Format(time.RFC3339),
				NotAfter:   notAfter.Format(time.RFC3339),
				PublicJWK:  mapPublicJWK,
				PrivateJWK: mapPrivateJWK,
			})

			currentNotBefore = shared.AddMonth(notAfter, int(0-overlapMonths))
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
