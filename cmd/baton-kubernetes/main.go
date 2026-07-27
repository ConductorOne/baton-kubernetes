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
)

var version = "dev"

func main() {
	ctx := context.Background()

	_, cmd, err := sdkconfig.DefineConfiguration(
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

func getConnector(ctx context.Context, cfg *pkgconfig.Kubernetes) (types.ConnectorServer, error) {
	k, err := connector.NewFromConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return connectorbuilder.NewConnector(ctx, k)
}
