package main

import (
	"context"
	"fmt"
	"os"

	pkgconfig "github.com/conductorone/baton-kubernetes/pkg/config"
	"github.com/conductorone/baton-kubernetes/pkg/connector"
	sdkconfig "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/client-go/rest"
)

var version = "dev"

func main() {
	ctx := context.Background()

	// The SDK's built-in --sync-resource-types flag is not part of the connector
	// schema struct, so it is read from viper at connector construction time.
	var v *viper.Viper
	getConnector := func(ctx context.Context, cfg *pkgconfig.Kubernetes) (types.ConnectorServer, error) {
		k, err := connector.NewFromConfig(ctx, cfg, v.GetStringSlice("sync-resource-types"))
		if err != nil {
			return nil, err
		}
		return connectorbuilder.NewConnector(ctx, k)
	}

	// The capabilities sub-command instantiates the connector with an empty REST
	// config and every resource type registered, so the generated manifest
	// declares the full surface — including the opt-in workload types, which
	// carry the OptInRequired annotation but are excluded from the default sync.
	runnerOpts := []connectorrunner.Option{}
	if capBuilder, err := connector.New(ctx, &rest.Config{}, connector.WithSyncResources(connector.AllResourceTypeIDs)); err == nil {
		runnerOpts = append(runnerOpts, connectorrunner.WithDefaultCapabilitiesConnectorBuilder(capBuilder))
	}

	var cmd *cobra.Command
	var err error
	v, cmd, err = sdkconfig.DefineConfiguration(
		ctx,
		"baton-kubernetes",
		getConnector,
		pkgconfig.Configuration,
		runnerOpts...,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
