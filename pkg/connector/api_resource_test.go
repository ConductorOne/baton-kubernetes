package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func apiResourceBuilderFor(t *testing.T, useRoleAssignments bool) *apiResourceBuilder {
	t.Helper()
	return newAPIResourceBuilder(stubProvider{index: permissionFixture(t, useRoleAssignments)})
}

func TestAPIResourceBuilderList(t *testing.T) {
	b := apiResourceBuilderFor(t, false)

	resources, results, err := b.List(context.Background(), nil, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	assert.Nil(t, results, "everything fits on one page")

	byID := make(map[string]*v2.Resource, len(resources))
	for _, resource := range resources {
		byID[resource.GetId().GetResource()] = resource
	}

	// Namespace-scoped classes are parented to their namespace...
	nsClass := byID["apps:deployments@team-a"]
	require.NotNil(t, nsClass)
	assert.Equal(t, "deployments (apps) in team-a", nsClass.GetDisplayName())
	assert.Equal(t, ResourceTypeNamespace.Id, nsClass.GetParentResourceId().GetResourceType())
	assert.Equal(t, "team-a", nsClass.GetParentResourceId().GetResource())

	// ...and cluster-wide ones to the cluster singleton, so nothing is
	// unparented the way the old wildcard resources were.
	clusterClass := byID["core:pods@*"]
	require.NotNil(t, clusterClass)
	assert.Equal(t, "pods cluster-wide", clusterClass.GetDisplayName())
	assert.Equal(t, ResourceTypeCluster.Id, clusterClass.GetParentResourceId().GetResourceType())
	assert.Equal(t, clusterResourceID, clusterClass.GetParentResourceId().GetResource())

	// A subresource is its own authorization target, not a verb on pods.
	assert.NotNil(t, byID["core:pods/exec@team-a"])

	// Non-resource URLs are cluster-wide only.
	url := byID["_url:/healthz@*"]
	require.NotNil(t, url)
	assert.Equal(t, "/healthz cluster-wide", url.GetDisplayName())
}

func TestAPIResourceBuilderPaging(t *testing.T) {
	b := apiResourceBuilderFor(t, false)
	ctx := context.Background()

	total := len(b.provider.(stubProvider).index.Classes())
	require.Greater(t, total, 2)

	seen := make(map[string]bool, total)
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, total+1, "paging must terminate")

		resources, results, err := b.List(ctx, nil, rs.SyncOpAttrs{
			SyncID:    "sync-1",
			PageToken: pagination.Token{Token: token, Size: 2},
		})
		require.NoError(t, err)
		require.LessOrEqual(t, len(resources), 2)
		for _, resource := range resources {
			id := resource.GetId().GetResource()
			require.False(t, seen[id], "class %s emitted twice", id)
			seen[id] = true
		}
		if results == nil || results.NextPageToken == "" {
			break
		}
		token = results.NextPageToken
	}

	assert.Len(t, seen, total, "every class must be emitted exactly once across pages")
}

func TestAPIResourceBuilderEntitlements(t *testing.T) {
	b := apiResourceBuilderFor(t, false)

	resource, err := rs.NewResource("pods in team-a", ResourceTypeAPIResource, "core:pods@team-a")
	require.NoError(t, err)

	entitlements, _, err := b.Entitlements(context.Background(), resource, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)

	slugs := make([]string, 0, len(entitlements))
	for _, ent := range entitlements {
		slugs = append(slugs, ent.GetSlug())
		// Permissions are held by roles, never handed to identities directly.
		grantable := make([]string, 0, len(ent.GetGrantableTo()))
		for _, rt := range ent.GetGrantableTo() {
			grantable = append(grantable, rt.GetId())
		}
		assert.ElementsMatch(t, []string{
			ResourceTypeRole.Id, ResourceTypeClusterRole.Id, ResourceTypeRoleAssignment.Id,
		}, grantable)
	}
	// Only the verbs the rule names — nothing that could never be granted.
	assert.ElementsMatch(t, []string{verbCreate, verbGet}, slugs)
}

func TestAPIResourceBuilderUnknownResourceIsNotAnError(t *testing.T) {
	b := apiResourceBuilderFor(t, false)
	ctx := context.Background()

	// A class whose rule was deleted since the resource was written: a cluster
	// change, not a fault.
	stale, err := rs.NewResource("gone", ResourceTypeAPIResource, "core:widgets@team-a")
	require.NoError(t, err)

	entitlements, _, err := b.Entitlements(ctx, stale, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	assert.Empty(t, entitlements)

	grants, _, err := b.Grants(ctx, stale, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	assert.Empty(t, grants)
}

func TestAPIResourceBuilderGrantsAreExpandable(t *testing.T) {
	b := apiResourceBuilderFor(t, true)

	resource, err := rs.NewResource("pods cluster-wide", ResourceTypeAPIResource, "core:pods@*")
	require.NoError(t, err)

	grants, _, err := b.Grants(context.Background(), resource, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	require.Len(t, grants, 2, "one per verb the rule names")

	for _, g := range grants {
		// Sparse model: the (role, scope) assignment holds the permission, since
		// that is where a scope-matching membership entitlement lives.
		assert.Equal(t, ResourceTypeRoleAssignment.Id, g.GetPrincipal().GetId().GetResourceType())
		assert.Equal(t, "cluster:editor", g.GetPrincipal().GetId().GetResource())

		expandable := &v2.GrantExpandable{}
		annos := annotations.Annotations(g.GetAnnotations())
		ok, err := annos.Pick(expandable)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, []string{"role_assignment:cluster:editor:assigned"}, expandable.GetEntitlementIds())
	}
}
