package main

import (
	"context"

	pkgconfig "github.com/conductorone/baton-kubernetes/pkg/config"
	"github.com/conductorone/baton-kubernetes/pkg/connector"
	sdkconfig "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
)

var version = "dev"

func main() {
	ctx := context.Background()

	sdkconfig.RunConnector(
		ctx,
		"baton-kubernetes",
		version,
		pkgconfig.Configuration,
		connector.NewFromConfig,
		// The x509 scan behind kube_group membership is accumulated across the
		// pages of one sync and read back in a later phase by another builder, so
		// it needs a store that outlives a single process.
		connectorrunner.WithSessionStoreEnabled(),
		// The capabilities sub-command uses a client-free builder that declares
		// every resource type, so the generated manifest is complete even though
		// the default sync registers only the core RBAC types.
		connectorrunner.WithDefaultCapabilitiesConnectorBuilderV2(connector.DefaultCapabilitiesBuilder()),
	)
}
