// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package secret implements the secret provider plugin for scafctl.
// It retrieves encrypted secrets from the scafctl secrets store via
// HostService RPC calls without accessing the keychain directly.
package secret

import (
	"context"
	"fmt"
	"regexp"

	"github.com/Masterminds/semver/v3"
	"github.com/google/jsonschema-go/jsonschema"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	sdkhelper "github.com/oakwood-commons/scafctl-plugin-sdk/provider/schemahelper"
)

const (
	// ProviderName is the unique identifier for this provider.
	ProviderName = "secret"
	// Version is the semantic version of this provider.
	Version = "1.0.0"

	// OpGet is the operation type for retrieving a single secret.
	OpGet = "get"
	// OpList is the operation type for listing all secret names.
	OpList = "list"

	// FieldOperation is the input field name for the operation type.
	FieldOperation = "operation"
	// FieldName is the input field name for the secret name.
	FieldName = "name"
	// FieldPattern is the input field name for the regex pattern.
	FieldPattern = "pattern"
	// FieldRequired is the input field name for the required flag.
	FieldRequired = "required"
	// FieldFallback is the input field name for the fallback value.
	FieldFallback = "fallback"

	maxNameLen    = 253
	maxPatternLen = 512
)

// secretClient abstracts the host secret operations for testability.
type secretClient interface {
	GetSecret(ctx context.Context, name string) (value string, found bool, err error)
	ListSecrets(ctx context.Context, pattern string) ([]string, error)
}

// Plugin implements the sdkplugin.ProviderPlugin interface.
type Plugin struct {
	descriptor *sdkprovider.Descriptor
}

// NewPlugin creates a new secret provider plugin.
func NewPlugin() *Plugin {
	version, _ := semver.NewVersion(Version)

	return &Plugin{
		descriptor: &sdkprovider.Descriptor{
			Name:        ProviderName,
			DisplayName: "Secret",
			APIVersion:  "v1",
			Description: "Retrieves encrypted secrets from the scafctl secrets store",
			Version:     version,
			Category:    "security",
			Capabilities: []sdkprovider.Capability{
				sdkprovider.CapabilityFrom,
			},
			Schema:        buildSchema(),
			OutputSchemas: buildOutputSchemas(),
			Examples:      buildExamples(),
			Tags:          []string{"secret", "security", "credential"},
		},
	}
}

// GetProviders returns the list of providers exposed by this plugin.
func (*Plugin) GetProviders(_ context.Context) ([]string, error) {
	return []string{ProviderName}, nil
}

// GetProviderDescriptor returns the descriptor for the named provider.
func (p *Plugin) GetProviderDescriptor(_ context.Context, providerName string) (*sdkprovider.Descriptor, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	return p.descriptor, nil
}

// ConfigureProvider accepts host configuration.
func (*Plugin) ConfigureProvider(_ context.Context, providerName string, _ sdkplugin.ProviderConfig) error {
	if providerName != ProviderName {
		return fmt.Errorf("unknown provider: %s", providerName)
	}

	return nil
}

// ExecuteProvider performs the secret operation.
func (*Plugin) ExecuteProvider(ctx context.Context, providerName string, inputs map[string]any) (*sdkprovider.Output, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	return execute(ctx, inputs, nil)
}

// ExecuteProviderStream returns an error because streaming is not supported.
func (*Plugin) ExecuteProviderStream(_ context.Context, _ string, _ map[string]any, _ func(sdkplugin.StreamChunk)) error {
	return sdkplugin.ErrStreamingNotSupported
}

// DescribeWhatIf returns a human-readable description of what the operation would do.
func (*Plugin) DescribeWhatIf(_ context.Context, providerName string, inputs map[string]any) (string, error) {
	if providerName != ProviderName {
		return "", fmt.Errorf("unknown provider: %s", providerName)
	}

	operation, _ := inputs[FieldOperation].(string)
	name, _ := inputs[FieldName].(string)
	pattern, _ := inputs[FieldPattern].(string)

	switch operation {
	case OpGet:
		if name != "" {
			return fmt.Sprintf("Would retrieve secret %q", name), nil
		}
		if pattern != "" {
			return fmt.Sprintf("Would retrieve first secret matching pattern %q", pattern), nil
		}
		return "Would retrieve a secret (name or pattern required)", nil
	case OpList:
		return "Would list available secrets", nil
	default:
		return fmt.Sprintf("Would perform secret operation %q", operation), nil
	}
}

// ExtractDependencies returns nil (no external dependencies).
func (*Plugin) ExtractDependencies(_ context.Context, _ string, _ map[string]any) ([]string, error) {
	return nil, nil
}

// StopProvider is a no-op.
func (*Plugin) StopProvider(_ context.Context, _ string) error {
	return nil
}

// execute performs the actual secret operation, using the provided client or
// falling back to the HostServiceClient from context.
func execute(ctx context.Context, inputs map[string]any, client secretClient) (*sdkprovider.Output, error) {
	if sdkprovider.DryRunFromContext(ctx) {
		return executeDryRun(inputs)
	}

	if client == nil {
		hostClient := sdkplugin.HostClientFromContext(ctx)
		if hostClient == nil {
			return nil, fmt.Errorf("host service client not available")
		}
		client = hostClient
	}

	operation, ok := inputs[FieldOperation].(string)
	if !ok || operation == "" {
		return nil, fmt.Errorf("operation field is required and must be a string")
	}

	switch operation {
	case OpGet:
		return executeGet(ctx, client, inputs)
	case OpList:
		return executeList(ctx, client)
	default:
		return nil, fmt.Errorf("unsupported operation: %s (must be %q or %q)", operation, OpGet, OpList)
	}
}

// executeGet handles the 'get' operation.
func executeGet(ctx context.Context, client secretClient, inputs map[string]any) (*sdkprovider.Output, error) {
	name, hasName := inputs[FieldName].(string)
	pattern, hasPattern := inputs[FieldPattern].(string)

	if !hasName && !hasPattern {
		return nil, fmt.Errorf("either %q or %q field is required for get operation", FieldName, FieldPattern)
	}

	required := true
	if reqVal, ok := inputs[FieldRequired].(bool); ok {
		required = reqVal
	}

	fallback, _ := inputs[FieldFallback].(string)

	var secretName string
	if hasName {
		secretName = name
	} else {
		matched, err := findMatchingSecret(ctx, client, pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to find secret matching pattern %q: %w", pattern, err)
		}
		if matched == "" {
			if required {
				return nil, fmt.Errorf("no secret found matching pattern %q", pattern)
			}
			return &sdkprovider.Output{Data: fallback}, nil
		}
		secretName = matched
	}

	value, found, err := client.GetSecret(ctx, secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %q: %w", secretName, err)
	}

	if !found {
		if required {
			return nil, fmt.Errorf("secret %q not found", secretName)
		}
		return &sdkprovider.Output{Data: fallback}, nil
	}

	return &sdkprovider.Output{Data: value}, nil
}

// executeList handles the 'list' operation.
func executeList(ctx context.Context, client secretClient) (*sdkprovider.Output, error) {
	names, err := client.ListSecrets(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	return &sdkprovider.Output{Data: names}, nil
}

// findMatchingSecret finds the first secret name matching the given regex pattern.
func findMatchingSecret(ctx context.Context, client secretClient, pattern string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid regex pattern: %w", err)
	}

	names, err := client.ListSecrets(ctx, "")
	if err != nil {
		return "", fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, name := range names {
		if re.MatchString(name) {
			return name, nil
		}
	}

	return "", nil
}

// executeDryRun returns a dry-run response for any operation.
func executeDryRun(inputs map[string]any) (*sdkprovider.Output, error) {
	operation, _ := inputs[FieldOperation].(string)

	return &sdkprovider.Output{
		Data: map[string]any{
			"_dry_run": true,
			"message":  fmt.Sprintf("dry-run: secret %s operation would be executed", operation),
		},
	}, nil
}

// buildSchema constructs the input schema for the secret provider.
func buildSchema() *jsonschema.Schema {
	return sdkhelper.ObjectSchema([]string{FieldOperation}, map[string]*jsonschema.Schema{
		FieldOperation: sdkhelper.StringProp(
			"Operation to perform: 'get' (retrieve single secret) or 'list' (list all secrets)",
			sdkhelper.WithEnum(OpGet, OpList),
			sdkhelper.WithExample(OpGet),
		),
		FieldName: sdkhelper.StringProp(
			"Secret name (for 'get' operation). Required if pattern not specified.",
			sdkhelper.WithExample("api-token"),
			sdkhelper.WithPattern("^[a-zA-Z0-9._-]+$"),
			sdkhelper.WithMaxLength(maxNameLen),
		),
		FieldPattern: sdkhelper.StringProp(
			"Regular expression pattern to match secret names (for 'get' operation). Returns first match.",
			sdkhelper.WithExample("^prod-.+$"),
			sdkhelper.WithMaxLength(maxPatternLen),
		),
		FieldRequired: sdkhelper.BoolProp(
			"If true, error when secret not found. If false, return fallback or empty string.",
			sdkhelper.WithExample(true),
		),
		FieldFallback: sdkhelper.StringProp(
			"Value to return when secret not found and required=false",
			sdkhelper.WithExample("default-value"),
		),
	})
}

// buildOutputSchemas documents the output format for each capability.
func buildOutputSchemas() map[sdkprovider.Capability]*jsonschema.Schema {
	return map[sdkprovider.Capability]*jsonschema.Schema{
		sdkprovider.CapabilityFrom: sdkhelper.ObjectSchema(nil, map[string]*jsonschema.Schema{
			"_result": sdkhelper.AnyProp(
				"For 'get' operation: the secret value as a string. For 'list' operation: array of secret names.",
				sdkhelper.WithExample("my-secret-value"),
			),
		}),
	}
}

// buildExamples provides configuration examples.
func buildExamples() []sdkprovider.Example {
	return []sdkprovider.Example{
		{
			Name:        "Get secret by name",
			Description: "Retrieve a specific secret",
			YAML: `name: get-api-token
provider: secret
inputs:
  operation: get
  name: api-token
  required: true`,
		},
		{
			Name:        "Get secret with fallback",
			Description: "Retrieve secret or use default value",
			YAML: `name: get-optional-token
provider: secret
inputs:
  operation: get
  name: optional-token
  required: false
  fallback: default-token`,
		},
		{
			Name:        "Get secret by pattern",
			Description: "Find and retrieve first secret matching regex pattern",
			YAML: `name: get-prod-secret
provider: secret
inputs:
  operation: get
  pattern: ^prod-.+$
  required: true`,
		},
		{
			Name:        "List all secrets",
			Description: "Get names of all stored secrets",
			YAML: `name: list-all-secrets
provider: secret
inputs:
  operation: list`,
		},
	}
}
