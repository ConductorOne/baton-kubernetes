package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

// sealedScanAttrs returns SyncOpAttrs whose session store already holds a sealed
// x509 scan, simulating the state after kubeUserBuilder.List() Phase 3 completed.
func sealedScanAttrs(t *testing.T, groupMembers map[string][]string) rs.SyncOpAttrs {
	t.Helper()
	store := newMemorySessionStore()
	require.True(t, storeSecretsScan(context.Background(), store, &secretsScanResult{
		GroupMembers: groupMembers,
		Sealed:       true,
	}))
	return rs.SyncOpAttrs{Session: store}
}

func groupResource(name string) *v2.Resource {
	return &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: ResourceTypeKubeGroup.Id,
			Resource:     name,
		},
	}
}

// TestKubeGroupBuilderGrantsReadsScan verifies that Grants() returns correct
// group membership from the sealed x509 scan without scanning any secrets.
func TestKubeGroupBuilderGrantsReadsScan(t *testing.T) {
	builder := newKubeGroupBuilder(fake.NewSimpleClientset())
	opts := sealedScanAttrs(t, map[string][]string{"dev-team": {"alice"}})

	grants, results, err := builder.Grants(context.Background(), groupResource("dev-team"), opts)

	require.NoError(t, err)
	assert.Empty(t, syncNextToken(results), "Grants must complete in one call")
	require.Len(t, grants, 1)
	assert.Equal(t, "alice", grants[0].Principal.Id.Resource)
}

// TestKubeGroupBuilderGrantsEmptyGroup verifies that a group with no members
// returns no grants.
func TestKubeGroupBuilderGrantsEmptyGroup(t *testing.T) {
	builder := newKubeGroupBuilder(fake.NewSimpleClientset())
	opts := sealedScanAttrs(t, map[string][]string{})

	grants, results, err := builder.Grants(context.Background(), groupResource("empty-group"), opts)

	require.NoError(t, err)
	assert.Empty(t, syncNextToken(results))
	assert.Empty(t, grants)
}

// TestKubeGroupBuilderGrantsMultipleGroups verifies that a user in multiple groups
// appears as a grant principal for each group independently.
func TestKubeGroupBuilderGrantsMultipleGroups(t *testing.T) {
	builder := newKubeGroupBuilder(fake.NewSimpleClientset())
	opts := sealedScanAttrs(t, map[string][]string{
		"group-a": {"bob"},
		"group-b": {"bob"},
	})

	for _, groupName := range []string{"group-a", "group-b"} {
		grants, _, err := builder.Grants(context.Background(), groupResource(groupName), opts)
		require.NoError(t, err)
		require.Len(t, grants, 1, "group %s should have bob as member", groupName)
		assert.Equal(t, "bob", grants[0].Principal.Id.Resource)
	}
}

// TestKubeGroupBuilderGrantsMultipleMembers verifies that a group with multiple members
// returns one grant per member.
func TestKubeGroupBuilderGrantsMultipleMembers(t *testing.T) {
	builder := newKubeGroupBuilder(fake.NewSimpleClientset())
	opts := sealedScanAttrs(t, map[string][]string{"platform": {"alice", "bob"}})

	grants, results, err := builder.Grants(context.Background(), groupResource("platform"), opts)

	require.NoError(t, err)
	assert.Empty(t, syncNextToken(results))
	require.Len(t, grants, 2, "platform group should have 2 members")

	principals := map[string]bool{}
	for _, g := range grants {
		assert.Equal(t, ResourceTypeKubeUser.Id, g.Principal.Id.ResourceType)
		principals[g.Principal.Id.Resource] = true
	}
	assert.True(t, principals["alice"])
	assert.True(t, principals["bob"])
}

// TestKubeGroupBuilderGrantsNoScan verifies that Grants() degrades to emitting no
// grants when the x509 scan never ran — e.g. kube_group is synced without
// kube_user via a custom sync selection. Membership is best-effort data and must
// not fail the sync.
func TestKubeGroupBuilderGrantsNoScan(t *testing.T) {
	builder := newKubeGroupBuilder(fake.NewSimpleClientset())

	grants, _, err := builder.Grants(context.Background(), groupResource("some-group"),
		rs.SyncOpAttrs{Session: newMemorySessionStore()})

	require.NoError(t, err, "Grants() must not fail when the x509 scan never ran")
	assert.Empty(t, grants, "no membership data means no grants")
}

// TestKubeGroupBuilderGrantsNoSessionStore verifies the same degradation when no
// session store is configured at all.
//
// The store is the one the SDK would actually hand a syncer, not a bare nil:
// connectorbuilder.WithSyncId returns a non-nil wrapper even around a nil store,
// which is what an embedder gets from connectorbuilder.NewConnector without
// WithSessionStore — the shape baton-eks, baton-aks and baton-gke build today.
// Calling through it dereferences the nil inner store, so a `Session: nil`
// SyncOpAttrs would pass this test while every embedder panicked.
func TestKubeGroupBuilderGrantsNoSessionStore(t *testing.T) {
	builder := newKubeGroupBuilder(fake.NewSimpleClientset())

	for _, tc := range []struct {
		name    string
		session sessions.SessionStore
	}{
		{"nil session", nil},
		{"sdk wrapper around a nil store", connectorbuilder.WithSyncId(nil, "sync-1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grants, _, err := builder.Grants(context.Background(), groupResource("some-group"),
				rs.SyncOpAttrs{Session: tc.session})

			require.NoError(t, err, "Grants() must not fail without a usable session store")
			assert.Empty(t, grants)
		})
	}
}

// TestSecretsScanSurvivesUnusableStore covers the write side of the same shape:
// kubeUserBuilder.List Phase 3 must not take down the mandatory user sync just
// because the embedder wired no session store.
func TestSecretsScanSurvivesUnusableStore(t *testing.T) {
	ctx := context.Background()
	unusable := connectorbuilder.WithSyncId(nil, "sync-1")

	assert.NotPanics(t, func() {
		assert.False(t, storeSecretsScan(ctx, unusable, newSecretsScanResult()))
	})
	assert.NotPanics(t, func() {
		_, found := loadSecretsScan(ctx, unusable)
		assert.False(t, found)
	})
}

// TestKubeGroupBuilderGrantsIgnoresUnsealedScan verifies that a scan still being
// accumulated is not read as membership fact. A partial scan under-reports
// membership, which for a reviewer is worse than reporting none.
func TestKubeGroupBuilderGrantsIgnoresUnsealedScan(t *testing.T) {
	store := newMemorySessionStore()
	require.True(t, storeSecretsScan(context.Background(), store, &secretsScanResult{
		GroupMembers: map[string][]string{"dev-team": {"alice"}},
		Sealed:       false,
	}))

	builder := newKubeGroupBuilder(fake.NewSimpleClientset())
	grants, _, err := builder.Grants(context.Background(), groupResource("dev-team"), rs.SyncOpAttrs{Session: store})

	require.NoError(t, err)
	assert.Empty(t, grants, "an unsealed scan must not produce grants")
}

// TestSecretsScanIsolatedPerSync verifies that the sync-scoped store the SDK
// hands each syncer keeps one sync's scan invisible to the next. Without this,
// a resumed or subsequent sync could read stale membership.
func TestSecretsScanIsolatedPerSync(t *testing.T) {
	ctx := context.Background()
	backing := newMemorySessionStore()

	syncOne := sessionForSync(backing, "sync-1")
	require.True(t, storeSecretsScan(ctx, syncOne, &secretsScanResult{
		GroupMembers: map[string][]string{"dev-team": {"alice"}},
		Sealed:       true,
	}))

	_, found := loadSecretsScan(ctx, sessionForSync(backing, "sync-2"))
	assert.False(t, found, "sync-2 must not see sync-1's scan")

	got, found := loadSecretsScan(ctx, syncOne)
	require.True(t, found)
	assert.Equal(t, []string{"alice"}, got.GroupMembers["dev-team"])
}

// sessionForSync mirrors how the SDK scopes a store to one sync before handing
// it to a resource syncer (connectorbuilder.WithSyncId).
func sessionForSync(store sessions.SessionStore, syncID string) sessions.SessionStore {
	return &syncScopedStore{SessionStore: store, syncID: syncID}
}

type syncScopedStore struct {
	sessions.SessionStore
	syncID string
}

func (s *syncScopedStore) Get(ctx context.Context, key string, opt ...sessions.SessionStoreOption) ([]byte, bool, error) {
	return s.SessionStore.Get(ctx, key, append([]sessions.SessionStoreOption{sessions.WithSyncID(s.syncID)}, opt...)...)
}

func (s *syncScopedStore) Set(ctx context.Context, key string, value []byte, opt ...sessions.SessionStoreOption) error {
	return s.SessionStore.Set(ctx, key, value, append([]sessions.SessionStoreOption{sessions.WithSyncID(s.syncID)}, opt...)...)
}
