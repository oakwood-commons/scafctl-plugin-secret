// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"context"
	"errors"
	"sort"
	"testing"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretClient implements secretClient for testing.
type mockSecretClient struct {
	secrets map[string]string
	getErr  error
	listErr error
}

func (m *mockSecretClient) GetSecret(_ context.Context, name string) (string, bool, error) {
	if m.getErr != nil {
		return "", false, m.getErr
	}
	val, ok := m.secrets[name]
	return val, ok, nil
}

func (m *mockSecretClient) ListSecrets(_ context.Context, _ string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	names := make([]string, 0, len(m.secrets))
	for name := range m.secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func TestNewPlugin(t *testing.T) {
	p := NewPlugin()

	assert.NotNil(t, p)
	assert.NotNil(t, p.descriptor)
	assert.Equal(t, ProviderName, p.descriptor.Name)
	assert.Equal(t, "Secret", p.descriptor.DisplayName)
	assert.Equal(t, "v1", p.descriptor.APIVersion)
	assert.Equal(t, "security", p.descriptor.Category)
	assert.NotNil(t, p.descriptor.Schema)
	assert.NotNil(t, p.descriptor.OutputSchemas)
	assert.NotEmpty(t, p.descriptor.Examples)
	assert.Len(t, p.descriptor.Capabilities, 1)
	assert.Equal(t, sdkprovider.CapabilityFrom, p.descriptor.Capabilities[0])
}

func TestGetProviders(t *testing.T) {
	p := NewPlugin()
	providers, err := p.GetProviders(context.Background())

	require.NoError(t, err)
	assert.Equal(t, []string{ProviderName}, providers)
}

func TestGetProviderDescriptor(t *testing.T) {
	p := NewPlugin()

	t.Run("known provider", func(t *testing.T) {
		desc, err := p.GetProviderDescriptor(context.Background(), ProviderName)
		require.NoError(t, err)
		assert.Equal(t, ProviderName, desc.Name)
		assert.Contains(t, desc.Schema.Properties, FieldOperation)
		assert.Contains(t, desc.Schema.Properties, FieldName)
		assert.Contains(t, desc.Schema.Properties, FieldPattern)
		assert.Contains(t, desc.Schema.Properties, FieldRequired)
		assert.Contains(t, desc.Schema.Properties, FieldFallback)

		opField := desc.Schema.Properties[FieldOperation]
		assert.Equal(t, []any{OpGet, OpList}, opField.Enum)
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := p.GetProviderDescriptor(context.Background(), "unknown")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

func TestExecuteGet_Success(t *testing.T) {
	client := &mockSecretClient{
		secrets: map[string]string{
			"api-token": "my-secret-value",
		},
	}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldName:      "api-token",
		FieldRequired:  true,
	}

	result, err := execute(context.Background(), inputs, client)
	require.NoError(t, err)
	assert.Equal(t, "my-secret-value", result.Data)
}

func TestExecuteGet_NotFoundRequired(t *testing.T) {
	client := &mockSecretClient{secrets: map[string]string{}}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldName:      "missing",
		FieldRequired:  true,
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestExecuteGet_NotFoundWithFallback(t *testing.T) {
	client := &mockSecretClient{secrets: map[string]string{}}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldName:      "missing",
		FieldRequired:  false,
		FieldFallback:  "default-value",
	}

	result, err := execute(context.Background(), inputs, client)
	require.NoError(t, err)
	assert.Equal(t, "default-value", result.Data)
}

func TestExecuteGet_RequiredDefaultTrue(t *testing.T) {
	client := &mockSecretClient{secrets: map[string]string{}}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldName:      "missing",
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestExecuteGet_PatternMatch(t *testing.T) {
	client := &mockSecretClient{
		secrets: map[string]string{
			"dev-token":  "dev-value",
			"prod-token": "prod-value",
		},
	}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldPattern:   "^prod-.+$",
		FieldRequired:  true,
	}

	result, err := execute(context.Background(), inputs, client)
	require.NoError(t, err)
	assert.Equal(t, "prod-value", result.Data)
}

func TestExecuteGet_PatternNoMatch(t *testing.T) {
	client := &mockSecretClient{
		secrets: map[string]string{
			"dev-token": "dev-value",
		},
	}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldPattern:   "^prod-.+$",
		FieldRequired:  true,
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no secret found matching pattern")
}

func TestExecuteGet_PatternNoMatchWithFallback(t *testing.T) {
	client := &mockSecretClient{
		secrets: map[string]string{
			"dev-token": "dev-value",
		},
	}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldPattern:   "^staging-.+$",
		FieldRequired:  false,
		FieldFallback:  "fallback-val",
	}

	result, err := execute(context.Background(), inputs, client)
	require.NoError(t, err)
	assert.Equal(t, "fallback-val", result.Data)
}

func TestExecuteGet_PatternInvalidRegex(t *testing.T) {
	client := &mockSecretClient{
		secrets: map[string]string{"test": "value"},
	}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldPattern:   "[invalid((",
		FieldRequired:  true,
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func TestExecuteGet_MissingNameAndPattern(t *testing.T) {
	client := &mockSecretClient{secrets: map[string]string{}}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldRequired:  true,
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "either")
}

func TestExecuteGet_StoreError(t *testing.T) {
	client := &mockSecretClient{
		secrets: map[string]string{},
		getErr:  errors.New("store error"),
	}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldName:      "test",
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get secret")
}

func TestExecuteGet_PatternListError(t *testing.T) {
	client := &mockSecretClient{
		secrets: map[string]string{},
		listErr: errors.New("list error"),
	}

	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldPattern:   "^prod-.+$",
		FieldRequired:  true,
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find secret matching pattern")
}

func TestExecuteList_Success(t *testing.T) {
	client := &mockSecretClient{
		secrets: map[string]string{
			"secret-a": "value1",
			"secret-b": "value2",
		},
	}

	inputs := map[string]any{
		FieldOperation: OpList,
	}

	result, err := execute(context.Background(), inputs, client)
	require.NoError(t, err)

	names, ok := result.Data.([]string)
	require.True(t, ok)
	assert.Len(t, names, 2)
	assert.Contains(t, names, "secret-a")
	assert.Contains(t, names, "secret-b")
}

func TestExecuteList_Empty(t *testing.T) {
	client := &mockSecretClient{secrets: map[string]string{}}

	inputs := map[string]any{
		FieldOperation: OpList,
	}

	result, err := execute(context.Background(), inputs, client)
	require.NoError(t, err)

	names, ok := result.Data.([]string)
	require.True(t, ok)
	assert.Empty(t, names)
}

func TestExecuteList_StoreError(t *testing.T) {
	client := &mockSecretClient{
		secrets: map[string]string{},
		listErr: errors.New("store error"),
	}

	inputs := map[string]any{
		FieldOperation: OpList,
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list secrets")
}

func TestExecute_MissingOperation(t *testing.T) {
	client := &mockSecretClient{secrets: map[string]string{}}

	inputs := map[string]any{
		FieldName: "test",
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "operation field is required")
}

func TestExecute_UnsupportedOperation(t *testing.T) {
	client := &mockSecretClient{secrets: map[string]string{}}

	inputs := map[string]any{
		FieldOperation: "invalid",
	}

	_, err := execute(context.Background(), inputs, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported operation")
}

func TestExecute_NoHostClient(t *testing.T) {
	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldName:      "test",
	}

	_, err := execute(context.Background(), inputs, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host service client not available")
}

func TestExecute_DryRun(t *testing.T) {
	ctx := sdkprovider.WithDryRun(context.Background(), true)

	tests := []struct {
		name      string
		operation string
		wantMsg   string
	}{
		{"get", OpGet, "dry-run: secret get operation"},
		{"list", OpList, "dry-run: secret list operation"},
		{"empty", "", "dry-run: secret  operation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputs := map[string]any{FieldOperation: tt.operation}

			result, err := execute(ctx, inputs, nil)
			require.NoError(t, err)

			resultMap, ok := result.Data.(map[string]any)
			require.True(t, ok)
			assert.True(t, resultMap["_dry_run"].(bool))
			assert.Contains(t, resultMap["message"], tt.wantMsg)
		})
	}
}

func TestDescribeWhatIf(t *testing.T) {
	p := NewPlugin()
	ctx := context.Background()

	tests := []struct {
		name    string
		inputs  map[string]any
		want    string
		wantErr bool
	}{
		{
			name:   "get by name",
			inputs: map[string]any{FieldOperation: OpGet, FieldName: "api-key"},
			want:   `Would retrieve secret "api-key"`,
		},
		{
			name:   "get by pattern",
			inputs: map[string]any{FieldOperation: OpGet, FieldPattern: "^prod-"},
			want:   `Would retrieve first secret matching pattern "^prod-"`,
		},
		{
			name:   "get no name or pattern",
			inputs: map[string]any{FieldOperation: OpGet},
			want:   "Would retrieve a secret (name or pattern required)",
		},
		{
			name:   "list",
			inputs: map[string]any{FieldOperation: OpList},
			want:   "Would list available secrets",
		},
		{
			name:   "unknown operation",
			inputs: map[string]any{FieldOperation: "delete"},
			want:   `Would perform secret operation "delete"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.DescribeWhatIf(ctx, ProviderName, tt.inputs)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDescribeWhatIf_UnknownProvider(t *testing.T) {
	p := NewPlugin()
	_, err := p.DescribeWhatIf(context.Background(), "unknown", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestConfigureProvider(t *testing.T) {
	p := NewPlugin()

	t.Run("known provider", func(t *testing.T) {
		err := p.ConfigureProvider(context.Background(), ProviderName, sdkplugin.ProviderConfig{})
		require.NoError(t, err)
	})

	t.Run("unknown provider", func(t *testing.T) {
		err := p.ConfigureProvider(context.Background(), "unknown", sdkplugin.ProviderConfig{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

func TestExecuteProvider_UnknownProvider(t *testing.T) {
	p := NewPlugin()
	_, err := p.ExecuteProvider(context.Background(), "unknown", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestExecuteProviderStream(t *testing.T) {
	p := NewPlugin()
	err := p.ExecuteProviderStream(context.Background(), ProviderName, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, sdkplugin.ErrStreamingNotSupported)
}

func TestExtractDependencies(t *testing.T) {
	p := NewPlugin()
	deps, err := p.ExtractDependencies(context.Background(), ProviderName, nil)
	require.NoError(t, err)
	assert.Nil(t, deps)
}

func TestStopProvider(t *testing.T) {
	p := NewPlugin()
	err := p.StopProvider(context.Background(), ProviderName)
	require.NoError(t, err)
}
