package aws

import (
	"context"
	"errors"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// fakeSSMGetter is an in-memory stand-in for the SSM GetParameter API used by
// the credential loader. It records the parameter names requested so tests can
// assert both parameters were read.
type fakeSSMGetter struct {
	mu       sync.Mutex
	params   map[string]string
	err      error
	requests []string
}

func (f *fakeSSMGetter) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, awssdk.ToString(in.Name))
	if f.err != nil {
		return nil, f.err
	}
	val, ok := f.params[awssdk.ToString(in.Name)]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Value: awssdk.String(val)},
	}, nil
}

// GetSecretValue API.
type fakeSecretGetter struct {
	secretString string
	err          error
}

func (f *fakeSecretGetter) GetSecretValue(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: awssdk.String(f.secretString)}, nil
}

func TestLoadSSMCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := &fakeSSMGetter{params: map[string]string{
		"/fig/client_id":     "the-id",
		"/fig/client_secret": "the-secret",
	}}

	creds, err := loadSSMCredentials(ctx, fake, "/fig/client_id", "/fig/client_secret")
	if err != nil {
		t.Fatalf("loadSSMCredentials: %v", err)
	}
	if creds.ClientID != "the-id" {
		t.Fatalf("ClientID = %q, want %q", creds.ClientID, "the-id")
	}
	if creds.ClientSecret != "the-secret" {
		t.Fatalf("ClientSecret = %q, want %q", creds.ClientSecret, "the-secret")
	}
}

func TestLoadSSMCredentialsGetError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	fake := &fakeSSMGetter{err: sentinel}

	_, err := loadSSMCredentials(context.Background(), fake, "/fig/client_id", "/fig/client_secret")
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the GetParameter failure", err)
	}
}

func TestLoadSecretsManagerCredentials(t *testing.T) {
	t.Parallel()
	fake := &fakeSecretGetter{secretString: `{"client_id":"the-id","client_secret":"the-secret"}`} //nolint:gosec // test fixture, not a real secret

	creds, err := loadSecretsManagerCredentials(context.Background(), fake, "fig/falcon", "client_id", "client_secret")
	if err != nil {
		t.Fatalf("loadSecretsManagerCredentials: %v", err)
	}
	if creds.ClientID != "the-id" || creds.ClientSecret != "the-secret" {
		t.Fatalf("creds = %+v, want the-id/the-secret", creds)
	}
}

func TestLoadSecretsManagerCredentialsMissingKey(t *testing.T) {
	t.Parallel()
	fake := &fakeSecretGetter{secretString: `{"client_id":"the-id"}`} //nolint:gosec // test fixture, not a real secret

	_, err := loadSecretsManagerCredentials(context.Background(), fake, "fig/falcon", "client_id", "client_secret")
	if err == nil {
		t.Fatal("missing client_secret key = nil error, want error")
	}
}

func TestLoadSecretsManagerCredentialsInvalidJSON(t *testing.T) {
	t.Parallel()
	fake := &fakeSecretGetter{secretString: `not json`}

	_, err := loadSecretsManagerCredentials(context.Background(), fake, "fig/falcon", "client_id", "client_secret")
	if err == nil {
		t.Fatal("invalid JSON secret = nil error, want error")
	}
}

func TestLoadFalconCredentialsUnknownStore(t *testing.T) {
	t.Parallel()
	_, err := LoadFalconCredentials(context.Background(), CredentialStoreConfig{Store: "vault"})
	if err == nil {
		t.Fatal("unknown store = nil error, want error")
	}
}
