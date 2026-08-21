package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// loadConfig resolves an AWS SDK configuration from the ambient credential and
// region chain (environment, shared config, instance profile, IRSA). A
// non-empty region overrides the region the chain would otherwise select; an
// empty region leaves the chain's choice in place.
func loadConfig(ctx context.Context, region string) (awssdk.Config, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awssdk.Config{}, fmt.Errorf("aws: loading config: %w", err)
	}
	return cfg, nil
}
