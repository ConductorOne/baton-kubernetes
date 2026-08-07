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
		// Sync only the core RBAC types unless told otherwise. This is a filter
		// rather than a narrower set of registered syncers, because the connector
		// must advertise every type it supports or the platform's own selection
		// fails validation -- see NewFromConfig.
		//
		// It is the weakest of the three sources, which is what makes it safe:
		// the SDK appends its own --sync-resource-types option after this one
		// when the flag is set, and in service mode the per-task selection from
		// the C1 UI takes precedence over local config. So this only decides the
		// bare local default.
		connectorrunner.WithSyncResourceTypeIDs(connector.DefaultSyncResourceTypeIDs()),
		// The capabilities sub-command uses a client-free builder that declares
		// every resource type, so the generated manifest is complete even though
		// the default sync registers only the core RBAC types.
		connectorrunner.WithDefaultCapabilitiesConnectorBuilderV2(connector.DefaultCapabilitiesBuilder()),
	)
}
