package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// FalconCredentials is a resolved Falcon API client id/secret pair loaded from
// an external credential store. Both fields are secret and must never be
// logged.
type FalconCredentials struct {
	ClientID     string
	ClientSecret string
}

// CredentialStoreConfig describes where to load Falcon credentials from. It is
// a plain-data copy of the relevant config sections, keeping this loader
// decoupled from the config package's mutation surface: the composition root
// fills it in and applies the result.
type CredentialStoreConfig struct {
	// Store selects the backend: "ssm" or "secrets_manager".
	Store string

	// SSM store: the region and the names of the two SecureString parameters
	// holding the client id and secret.
	SSMRegion            string
	SSMClientIDParam     string
	SSMClientSecretParam string

	// Secrets Manager store: the region, the secret name, and the two JSON keys
	// within the secret value.
	SecretsRegion         string
	SecretName            string
	SecretClientIDKey     string
	SecretClientSecretKey string
}

// ssmGetter is the subset of the SSM client the credential loader needs.
type ssmGetter interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// secretGetter is the subset of the Secrets Manager client the credential
// loader needs.
type secretGetter interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// LoadFalconCredentials resolves Falcon API credentials from the configured
// external store. The "ssm" store reads two decrypted SecureString parameters
// (client id and secret); the "secrets_manager" store reads one JSON secret and
// extracts two keys. Any other store value is an error.
//
// The returned credentials are secret; callers must never log them.
func LoadFalconCredentials(ctx context.Context, in CredentialStoreConfig) (FalconCredentials, error) {
	switch in.Store {
	case "ssm":
		cfg, err := loadConfig(ctx, in.SSMRegion)
		if err != nil {
			return FalconCredentials{}, err
		}
		return loadSSMCredentials(ctx, ssm.NewFromConfig(cfg), in.SSMClientIDParam, in.SSMClientSecretParam)
	case "secrets_manager":
		cfg, err := loadConfig(ctx, in.SecretsRegion)
		if err != nil {
			return FalconCredentials{}, err
		}
		return loadSecretsManagerCredentials(ctx, secretsmanager.NewFromConfig(cfg), in.SecretName, in.SecretClientIDKey, in.SecretClientSecretKey)
	default:
		return FalconCredentials{}, fmt.Errorf("aws: unknown credentials store %q (want ssm|secrets_manager)", in.Store)
	}
}

// loadSSMCredentials reads the client id and secret from two SSM parameters,
// requesting decryption so SecureString parameters resolve to plaintext. It is
// the testable seam behind the "ssm" branch of LoadFalconCredentials.
func loadSSMCredentials(ctx context.Context, client ssmGetter, idParam, secretParam string) (FalconCredentials, error) {
	id, err := getSSMParameter(ctx, client, idParam)
	if err != nil {
		return FalconCredentials{}, err
	}
	secret, err := getSSMParameter(ctx, client, secretParam)
	if err != nil {
		return FalconCredentials{}, err
	}
	return FalconCredentials{ClientID: id, ClientSecret: secret}, nil
}

// getSSMParameter fetches one decrypted parameter value.
func getSSMParameter(ctx context.Context, client ssmGetter, name string) (string, error) {
	out, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           awssdk.String(name),
		WithDecryption: awssdk.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("aws: reading ssm parameter %q: %w", name, err)
	}
	if out.Parameter == nil || awssdk.ToString(out.Parameter.Value) == "" {
		return "", fmt.Errorf("aws: ssm parameter %q is empty", name)
	}
	return awssdk.ToString(out.Parameter.Value), nil
}

// loadSecretsManagerCredentials reads one JSON secret and extracts the client id
// and secret from the named keys. It is the testable seam behind the
// "secrets_manager" branch of LoadFalconCredentials.
func loadSecretsManagerCredentials(ctx context.Context, client secretGetter, secretName, idKey, secretKey string) (FalconCredentials, error) {
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: awssdk.String(secretName),
	})
	if err != nil {
		return FalconCredentials{}, fmt.Errorf("aws: reading secret %q: %w", secretName, err)
	}
	if out.SecretString == nil {
		return FalconCredentials{}, fmt.Errorf("aws: secret %q has no string value", secretName)
	}

	var fields map[string]string
	if err := json.Unmarshal([]byte(awssdk.ToString(out.SecretString)), &fields); err != nil {
		return FalconCredentials{}, fmt.Errorf("aws: parsing secret %q: %w", secretName, err)
	}

	id, ok := fields[idKey]
	if !ok || id == "" {
		return FalconCredentials{}, fmt.Errorf("aws: secret %q is missing key %q", secretName, idKey)
	}
	secret, ok := fields[secretKey]
	if !ok || secret == "" {
		return FalconCredentials{}, fmt.Errorf("aws: secret %q is missing key %q", secretName, secretKey)
	}
	return FalconCredentials{ClientID: id, ClientSecret: secret}, nil
}
