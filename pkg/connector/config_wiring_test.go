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

	k, _, err := NewFromConfig(context.Background(), &pkgconfig.Kubernetes{
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

	_, _, err := NewFromConfig(context.Background(), &pkgconfig.Kubernetes{}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no kubeconfig available")
}

// registeredResourceTypeIDs builds a connector from cfg and returns the resource
// type IDs it advertises, which is what the SDK validates a sync filter against.
func registeredResourceTypeIDs(t *testing.T, cfg *pkgconfig.Kubernetes) []string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KUBECONFIG", "")

	cfg.Server = "https://127.0.0.1:65535"
	cfg.Token = "fake-token"
	cfg.InsecureSkipTlsVerify = true

	builder, _, err := NewFromConfig(context.Background(), cfg, nil)
	require.NoError(t, err)

	ctx := context.Background()
	var ids []string
	for _, s := range builder.ResourceSyncers(ctx) {
		ids = append(ids, s.ResourceType(ctx).GetId())
	}
	return ids
}

// TestRegisteredResourceTypesCoverEverySelectableType pins the invariant that
// broke service mode.
//
// The platform's resource type selection arrives with each sync task, long after
// the connector was built from local config, and the SDK validates that
// selection against the types the connector advertised. A connector that
// registers only its default subset therefore fails the moment a tenant opts
// into one of the OptInRequired types:
//
//	invalid resource type 'configmap' in filter
//
// Registration must not depend on any selection: everything the capabilities
// manifest declares as selectable has to be registered, so no filter the
// platform can send is ever invalid.
func TestRegisteredResourceTypesCoverEverySelectableType(t *testing.T) {
	assert.ElementsMatch(t, AllResourceTypeIDs, registeredResourceTypeIDs(t, &pkgconfig.Kubernetes{}),
		"every non-sparse type a tenant can opt into must be registered")

	assert.ElementsMatch(t, DeclaredResourceTypeIDs(),
		registeredResourceTypeIDs(t, &pkgconfig.Kubernetes{UseRoleAssignments: true}),
		"with the sparse model on, its types must be registered too")
}

// TestDefaultSyncFilterIsRegistered verifies the core RBAC default is expressed
// as a filter over registered types rather than as a narrower registration —
// every id in it must be something the connector actually advertises, or the
// default would fail the same validation it exists to avoid.
func TestDefaultSyncFilterIsRegistered(t *testing.T) {
	registered := make(map[string]bool)
	for _, id := range registeredResourceTypeIDs(t, &pkgconfig.Kubernetes{}) {
		registered[id] = true
	}

	defaults := DefaultSyncResourceTypeIDs()
	require.NotEmpty(t, defaults)
	for _, id := range defaults {
		assert.True(t, registered[id], "default sync filter names unregistered type %q", id)
	}
	assert.Less(t, len(defaults), len(AllResourceTypeIDs),
		"the default must still be narrower than everything, or it is not a default")
}
