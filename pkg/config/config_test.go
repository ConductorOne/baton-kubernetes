package config_test

import (
	"testing"

	"github.com/conductorone/baton-kubernetes/pkg/config"
)

// TestConfigurationFields verifies every expected flag name appears in ConfigurationFields.
func TestConfigurationFields(t *testing.T) {
	want := []string{
		config.FlagKubeconfig,
		config.FlagCacheDir,
		config.FlagCertFile,
		config.FlagKeyFile,
		config.FlagBearerToken,
		config.FlagImpersonate,
		config.FlagImpersonateUID,
		config.FlagImpersonateGroup,
		config.FlagUsername,
		config.FlagPassword,
		config.FlagClusterName,
		config.FlagAuthInfoName,
		config.FlagNamespace,
		config.FlagContext,
		config.FlagAPIServer,
		config.FlagTLSServerName,
		config.FlagInsecure,
		config.FlagCAFile,
		config.FlagTimeout,
		config.FlagDisableCompression,
		config.FlagSyncConfigMaps,
		config.FlagSyncSecrets,
		config.FlagSyncPods,
		config.FlagSyncNodes,
		config.FlagSyncDeployments,
		config.FlagSyncStatefulSets,
		config.FlagSyncDaemonSets,
	}

	got := make(map[string]bool)
	for _, f := range config.ConfigurationFields {
		got[f.FieldName] = true
	}

	for _, name := range want {
		if !got[name] {
			t.Errorf("missing field %q in ConfigurationFields", name)
		}
	}

	if len(config.ConfigurationFields) != len(want) {
		t.Errorf("ConfigurationFields has %d fields, want %d", len(config.ConfigurationFields), len(want))
	}
}

// TestKubernetesImplementsConfigurable verifies the generated struct satisfies
// field.Configurable at compile time by calling each method.
func TestKubernetesImplementsConfigurable(t *testing.T) {
	var cfg config.Kubernetes
	_ = cfg.GetString("kubeconfig")
	_ = cfg.GetBool("insecure-skip-tls-verify")
	_ = cfg.GetStringSlice("as-group")
}
