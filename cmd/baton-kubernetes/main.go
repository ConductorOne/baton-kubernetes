package main

import (
	"context"
	"fmt"
	"os"

	pkgconfig "github.com/conductorone/baton-kubernetes/pkg/config"
	"github.com/conductorone/baton-kubernetes/pkg/connector"
	sdkconfig "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	var cmd *cobra.Command
	var err error
	v, cmd, err = sdkconfig.DefineConfiguration(
		ctx,
		"baton-kubernetes",
		getConnector,
		pkgconfig.Configuration,
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
