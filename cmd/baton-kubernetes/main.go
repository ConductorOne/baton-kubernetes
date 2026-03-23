package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-kubernetes/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()

	_, cmd, err := config.DefineConfiguration(
		ctx,
		"baton-kubernetes",
		getConnector,
		field.Configuration{
			Fields:      getConfigurationFields(),
			Constraints: getFieldRelationships(),
		},
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

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	opt, err := GetConfig(v)
	if err != nil {
		return nil, err
	}
	restConfig, err := opt.ToRESTConfig()
	if err != nil {
		l.Error("error creating rest config", zap.Error(err))
		return nil, fmt.Errorf("failed to create Kubernetes REST config: %w. Ensure you have a valid kubeconfig file or in-cluster configuration", err)
	}

	// Verify that the REST config isn't nil
	if restConfig == nil {
		l.Error("unexpectedly got nil REST config")
		return nil, fmt.Errorf("failed to create Kubernetes REST config: unexpectedly got nil config")
	}

	// Build the list of resource types to sync. Core RBAC resources are always
	// included. Workload/config resources are opt-in via flags because they
	// expose verb entitlements that never produce grants, resulting in noisy
	// partial resources in ConductorOne.
	syncResources := []string{
		"namespace",
		"service_account",
		"role",
		"cluster_role",
		"kube_user",
		"kube_group",
	}
	optionalResources := map[string]string{
		flagSyncConfigMaps:   "configmap",
		flagSyncSecrets:      "secret",
		flagSyncPods:         "pod",
		flagSyncNodes:        "node",
		flagSyncDeployments:  "deployment",
		flagSyncStatefulSets: "statefulset",
		flagSyncDaemonSets:   "daemonset",
	}
	for flag, resourceID := range optionalResources {
		if v.GetBool(flag) {
			syncResources = append(syncResources, resourceID)
		}
	}

	cb, err := connector.New(ctx, restConfig, connector.WithSyncResources(syncResources))
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}
	connector, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}
	return connector, nil
}
