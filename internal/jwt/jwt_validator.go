package jwt

import (
	"time"

	grpcdotnetgo_utils "github.com/fluffy-bunny/grpcdotnetgo/pkg/utils"
	"github.com/gogo/status"
	"github.com/lestrrat-go/jwx/jwk"
	jwxt "github.com/lestrrat-go/jwx/jwt"

	"google.golang.org/grpc/codes"
)

// JWTValidatorOptions is a struct for specifying configuration options.
type JWTValidatorOptions struct {
	ClockSkewMinutes  int
	ValidateSignature *bool
	RequiredIssuer    *string
	KeySet            jwk.Set
}

// JWTValidator struct
type JWTValidator struct {
	options      *JWTValidatorOptions
	parseOptions []jwxt.ParseOption
}

func validateJWTValidatorOptions(options *JWTValidatorOptions) error {
	if grpcdotnetgo_utils.IsEmptyOrNil(options) {
		return status.Error(codes.InvalidArgument, "options cannot be nil")
	}
	if grpcdotnetgo_utils.IsEmptyOrNil(options.KeySet) {
		return status.Error(codes.InvalidArgument, "options.KeySet cannot be nil")
	}
	if options.ClockSkewMinutes < 0 {
		return status.Error(codes.InvalidArgument, "options.ClockSkewMinutes cannot be less than 0")
	}
	return nil
}

// NewJWTValidator creates a new *JWTValidator
func NewJWTValidator(options *JWTValidatorOptions) (*JWTValidator, error) {
	err := validateJWTValidatorOptions(options)
	if err != nil {
		return nil, err
	}
	parseOptions := []jwxt.ParseOption{}
	if options.ValidateSignature != nil && *options.ValidateSignature {
		jwkSet := options.KeySet
		parseOptions = append(parseOptions, jwxt.WithKeySet(jwkSet))
	}

	return &JWTValidator{
		options:      options,
		parseOptions: parseOptions,
	}, nil
}
func (jwtValidator *JWTValidator) shouldValidateSignature() bool {
	if jwtValidator.options.ValidateSignature == nil {
		return false
	}
	return *jwtValidator.options.ValidateSignature
}
func (jwtValidator *JWTValidator) shouldValidateIssuer() bool {
	if !grpcdotnetgo_utils.IsEmptyOrNil(jwtValidator.options.RequiredIssuer) &&
		!grpcdotnetgo_utils.IsEmptyOrNil(*(jwtValidator.options.RequiredIssuer)) {
		return true
	}
	return false
}

// ParseTokenRaw validates an produces an inteface to the raw token artifacts
func (jwtValidator *JWTValidator) ParseTokenRaw(accessToken string) (jwxt.Token, error) {
	// Parse the JWT
	parseOptions := []jwxt.ParseOption{}
	if jwtValidator.shouldValidateSignature() {
		jwkSet := jwtValidator.options.KeySet
		parseOptions = append(parseOptions, jwxt.WithKeySet(jwkSet))
	}

	token, err := jwxt.ParseString(accessToken, parseOptions...)
	if err != nil {
		return nil, err
	}

	// This set had a key that worked
	var validationOpts []jwxt.ValidateOption
	if jwtValidator.shouldValidateIssuer() {
		validationOpts = append(validationOpts, jwxt.WithIssuer(*jwtValidator.options.RequiredIssuer))
	}
	// Allow clock skew
	validationOpts = append(validationOpts, jwxt.WithAcceptableSkew(time.Minute*time.Duration(jwtValidator.options.ClockSkewMinutes)))

	opts := validationOpts
	err = jwxt.Validate(token, opts...)
	if err != nil {
		return nil, err
	}
	return token, nil
}
