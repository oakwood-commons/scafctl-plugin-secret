// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"context"
	"testing"

	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
)

func BenchmarkExecuteGet(b *testing.B) {
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
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = execute(ctx, inputs, client)
	}
}

func BenchmarkExecuteList(b *testing.B) {
	client := &mockSecretClient{
		secrets: map[string]string{
			"secret-a": "value1",
			"secret-b": "value2",
			"secret-c": "value3",
		},
	}
	inputs := map[string]any{
		FieldOperation: OpList,
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = execute(ctx, inputs, client)
	}
}

func BenchmarkDescribeWhatIf(b *testing.B) {
	p := NewPlugin()
	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldName:      "api-token",
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = p.DescribeWhatIf(ctx, ProviderName, inputs)
	}
}

func BenchmarkDryRun(b *testing.B) {
	ctx := sdkprovider.WithDryRun(context.Background(), true)
	inputs := map[string]any{
		FieldOperation: OpGet,
		FieldName:      "api-token",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = execute(ctx, inputs, nil)
	}
}

func BenchmarkNewPlugin(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = NewPlugin()
	}
}
