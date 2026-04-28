// Package main is the entry point for the scafctl-plugin-secret plugin.
package main

import (
	"github.com/oakwood-commons/scafctl-plugin-secret/internal/secret"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func main() {
	sdkplugin.Serve(secret.NewPlugin())
}
