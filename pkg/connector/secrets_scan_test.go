package connector

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/connectorstore"
	"github.com/conductorone/baton-sdk/pkg/dotc1z"
	"github.com/conductorone/baton-sdk/pkg/dotc1z/c1zstore"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretsScanSurvivesStoreReopen is the regression test for the defect this
// migration exists to fix: kubeUserBuilder.List Phase 3 accumulates the x509 scan
// page by page, and kubeGroupBuilder.Grants reads it back in a later sync phase.
// While that state lived on the connector struct, a sync resumed in a fresh
// process reached the grants phase with nothing accumulated and silently emitted
// zero group-membership grants.
//
// The durability boundary is the c1z file, not the process: in local runs the
// session store handed to a syncer is backed by dotc1z (see
// dotc1z/c1file_store.go, C1File.SessionStore), and a resumed sync reopens that
// file. Closing and reopening the store is therefore what a fresh process does,
// so this exercises the real storage layer rather than a mock.
func TestSecretsScanSurvivesStoreReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "resume.c1z")
	var syncID string

	// Page 1 of Phase 3 finds alice and leaves the scan unsealed.
	withStore(t, ctx, path, func(store c1zstore.Store) {
		id, err := store.StartNewSync(ctx, connectorstore.SyncTypeFull, "")
		require.NoError(t, err)
		syncID = id

		require.True(t, storeSecretsScan(ctx, syncSession(store, syncID), &secretsScanResult{
			Usernames:    []string{"alice"},
			GroupMembers: map[string][]string{"dev-team": {"alice"}},
		}), "page 1 must persist the running scan")
	})

	// The process dies here. A resumed sync reopens the same c1z and continues
	// Phase 3 from its page token.
	withStore(t, ctx, path, func(store c1zstore.Store) {
		_, err := store.ResumeSync(ctx, connectorstore.SyncTypeFull, syncID)
		require.NoError(t, err)
		ss := syncSession(store, syncID)

		acc, ok := loadSecretsScan(ctx, ss)
		require.True(t, ok, "the resumed sync must recover page 1's scan")
		assert.False(t, acc.Sealed)
		assert.Equal(t, []string{"alice"}, acc.Usernames,
			"losing page 1 here is the bug: membership would be under-reported")

		// Page 2 finds bob and seals.
		acc.Usernames = append(acc.Usernames, "bob")
		acc.GroupMembers["dev-team"] = append(acc.GroupMembers["dev-team"], "bob")
		acc.GroupMembers["ops-team"] = []string{"bob"}
		acc.Sealed = true
		require.True(t, storeSecretsScan(ctx, ss, acc))
	})

	// The grants phase, in a third process, sees the complete scan.
	withStore(t, ctx, path, func(store c1zstore.Store) {
		_, err := store.ResumeSync(ctx, connectorstore.SyncTypeFull, syncID)
		require.NoError(t, err)

		result, ok := loadSecretsScan(ctx, syncSession(store, syncID))
		require.True(t, ok)
		require.True(t, result.Sealed, "kubeGroupBuilder.Grants only trusts a sealed scan")
		assert.ElementsMatch(t, []string{"alice", "bob"}, result.Usernames)
		assert.ElementsMatch(t, []string{"alice", "bob"}, result.GroupMembers["dev-team"])
		assert.ElementsMatch(t, []string{"bob"}, result.GroupMembers["ops-team"])

		// A later sync against the same c1z must not inherit any of it.
		_, ok = loadSecretsScan(ctx, syncSession(store, "a-later-sync"))
		assert.False(t, ok, "a different sync ID must not read this sync's scan")
	})
}

// syncSession scopes the store's session store to one sync, as the SDK does
// before handing it to a resource syncer.
func syncSession(store c1zstore.Store, syncID string) sessions.SessionStore {
	return connectorbuilder.WithSyncId(store.SessionStore(), syncID)
}

// withStore opens the c1z at path, runs fn, then closes the store so everything
// written is flushed back into the file.
//
// The PutResourceTypes call is load-bearing, not scaffolding: Close skips the
// save entirely unless something set the dbUpdated flag (dotc1z/c1file.go:642),
// and the session-store writes in dotc1z/session_store.go never set it. A real
// sync always writes resources alongside the scan, so this reproduces that.
// Without it the file is silently discarded and the assertions above would fail
// for a reason unrelated to the connector.
func withStore(t *testing.T, ctx context.Context, path string, fn func(c1zstore.Store)) {
	t.Helper()
	store, err := dotc1z.NewStore(ctx, path)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close(ctx)) }()

	fn(store)
	require.NoError(t, store.PutResourceTypes(ctx, ResourceTypeKubeUser))
}
