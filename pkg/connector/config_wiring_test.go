package connector

import (
	"context"
	"testing"

	pkgconfig "github.com/conductorone/baton-kubernetes/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewFromConfigExplicitServerSkipsKubeconfigGuard covers the documented
// bearer-token setup: an explicit --server plus --token on a host with no
// kubeconfig at all. The implicit-source guard exists to catch client-go's
// silent localhost:8080 fallback, which cannot happen once --server is set, so
// the guard must not reject this combination.
func TestNewFromConfigExplicitServerSkipsKubeconfigGuard(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KUBECONFIG", "")

	k, err := NewFromConfig(context.Background(), &pkgconfig.Kubernetes{
		Server:                "https://127.0.0.1:65535",
		Token:                 "fake-token",
		InsecureSkipTlsVerify: true,
	}, nil)

	require.NoError(t, err, "an explicit server plus token must not require a kubeconfig")
	require.NotNil(t, k)
}

// TestNewFromConfigNoSourceStillGuarded verifies the guard still fires when
// neither a kubeconfig nor an explicit server is available, rather than letting
// client-go fall back to localhost:8080 and report "connection refused".
func TestNewFromConfigNoSourceStillGuarded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KUBECONFIG", "")

	_, err := NewFromConfig(context.Background(), &pkgconfig.Kubernetes{}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no kubeconfig available")
}
