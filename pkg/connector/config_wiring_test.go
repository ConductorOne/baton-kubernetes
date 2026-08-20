package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pkgconfig "github.com/conductorone/baton-kubernetes/pkg/config"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes/fake"
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
	assert.ElementsMatch(t, DeclaredResourceTypeIDs(), registeredResourceTypeIDs(t, &pkgconfig.Kubernetes{}),
		"every type a tenant can opt into must be registered")

	// Including the sparse types, whose builders no-op while the flag is off.
	// Registering them conditionally would fail the same validation for
	// 'role_assignment', since the capabilities manifest offers it to tenants.
	assert.ElementsMatch(t, DeclaredResourceTypeIDs(),
		registeredResourceTypeIDs(t, &pkgconfig.Kubernetes{UseRoleAssignments: true}),
		"the registered set must not depend on the sparse flag")
}

// TestRoleAssignmentsEmitNothingWhenDisabled is the other half of registering the
// sparse type unconditionally: it must stay silent while the flag is off, or
// cluster role access would be counted twice.
//
// The cluster singleton has no such gate. It is one resource, both the sparse
// assignments and the cluster-wide api_resource targets anchor to it, and
// selecting the type is what asks for it.
func TestRoleAssignmentsEmitNothingWhenDisabled(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		clusterRole("view"),
		crbFor("view-everywhere", "view", userSubject("alice")),
	)

	assignments, _, err := newRoleAssignmentBuilder(client, &Kubernetes{client: client}, false).
		List(ctx, nil, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	assert.Empty(t, assignments, "role assignments must not be emitted alongside the flat model")

	clusters, _, err := newClusterBuilder("kind-test", "https://10.96.0.1:443").
		List(ctx, nil, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	require.Len(t, clusters, 1)
}

// TestDefaultSyncFilterCoversTheSparseTypes pins the regression the default
// filter caused: with --use-role-assignments on and no explicit selection, the
// core-six filter hid role_assignment and cluster while cluster_role was already
// suppressing its own entitlements and grants, so the sync emitted no cluster
// role access at all.
func TestDefaultSyncFilterCoversTheSparseTypes(t *testing.T) {
	defaults := make(map[string]bool)
	for _, id := range DefaultSyncResourceTypeIDs() {
		defaults[id] = true
	}

	assert.True(t, defaults[ResourceTypeRoleAssignment.Id],
		"the sparse model produces nothing if its own type is filtered out by default")
	assert.True(t, defaults[ResourceTypeCluster.Id],
		"cluster-scoped assignments need their scope resource synced or C1 drops the relationship")

	// api_resource is the only type that can express a permission over a class of
	// objects, and the collection verbs live nowhere else, so filtering it out of
	// the default would leave "who can create pods in team-a" unanswerable.
	assert.True(t, defaults[ResourceTypeAPIResource.Id])
}

// TestClusterNameIgnoresKubeconfigWhenServerIsExplicit covers the documented
// --server plus --token setup on a machine that also happens to hold a
// kubeconfig.
//
// RawConfig returns the merged kubeconfig without applying overrides, so reading
// a name from it there would label the cluster after whichever context that file
// points at rather than the server actually being talked to. Falling back to the
// host is less pretty and more honest.
func TestClusterNameIgnoresKubeconfigWhenServerIsExplicit(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters:
- name: stale-minikube
  cluster: {server: https://192.168.99.100:8443}
contexts:
- name: stale-minikube
  context: {cluster: stale-minikube, user: stale}
current-context: stale-minikube
users:
- name: stale
  user: {}
`), 0o600))
	t.Setenv("KUBECONFIG", kubeconfig)

	opt := clioptions.NewConfigFlags(true)
	opt.KubeConfig = &kubeconfig

	withServer := clusterNameFromConfig(opt, &pkgconfig.Kubernetes{Server: "https://prod.example.com"})
	assert.Empty(t, withServer, "an explicit --server must not inherit the kubeconfig's context name")

	// Without --server the kubeconfig is what is being talked to, so its name is
	// the best one available.
	assert.Equal(t, "stale-minikube", clusterNameFromConfig(opt, &pkgconfig.Kubernetes{}))

	// An explicitly named cluster always wins, --server or not.
	assert.Equal(t, "prod",
		clusterNameFromConfig(opt, &pkgconfig.Kubernetes{Server: "https://prod.example.com", Cluster: "prod"}))
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
