package connector

import (
	"context"
	"fmt"
	"sort"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func clusterRole(name string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func crbFor(name, roleName string, subjects ...rbacv1.Subject) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: RBACKindClusterRole, Name: roleName, APIGroup: RBACAPIGroup},
		Subjects:   subjects,
	}
}

func rbFor(name, namespace, roleKind, roleName string, subjects ...rbacv1.Subject) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		RoleRef:    rbacv1.RoleRef{Kind: roleKind, Name: roleName, APIGroup: RBACAPIGroup},
		Subjects:   subjects,
	}
}

func userSubject(name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: SubjectKindUser, Name: name, APIGroup: RBACAPIGroup}
}

// newRoleAssignmentFixture wires the builder over a fake cluster, using the real
// Kubernetes connector so the binding cache and lookups behave as in production.
func newRoleAssignmentFixture(objects ...runtime.Object) *roleAssignmentBuilder {
	client := fake.NewSimpleClientset(objects...)
	return newRoleAssignmentBuilder(client, &Kubernetes{client: client}, true)
}

// listAssignmentIDs drains List and returns the object IDs it emitted.
func listAssignmentIDs(t *testing.T, b *roleAssignmentBuilder, syncID string) []string {
	t.Helper()
	ctx := context.Background()
	var ids []string
	token := ""
	for {
		resources, results, err := b.List(ctx, nil, rs.SyncOpAttrs{SyncID: syncID, PageToken: paginationToken(token)})
		require.NoError(t, err)
		for _, r := range resources {
			ids = append(ids, r.GetId().GetResource())
		}
		next := ""
		if results != nil {
			next = results.NextPageToken
		}
		if next == "" {
			break
		}
		require.NotEqual(t, token, next, "page token must advance")
		token = next
	}
	sort.Strings(ids)
	return ids
}

// TestRoleAssignmentDedupesByRoleAndScope is the case that forced the deduped
// model: C1 keys a role-scope-binding relationship on (scope, role) alone and
// keeps only the last resource reporting it, so two bindings granting the same
// cluster role in the same namespace must collapse into one resource rather
// than two that silently overwrite each other.
func TestRoleAssignmentDedupesByRoleAndScope(t *testing.T) {
	b := newRoleAssignmentFixture(
		clusterRole("view"),
		rbFor("view-alice", "team-a", RBACKindClusterRole, "view", userSubject("alice")),
		rbFor("view-bob", "team-a", RBACKindClusterRole, "view", userSubject("bob")),
	)

	ids := listAssignmentIDs(t, b, "sync-1")
	assert.Equal(t, []string{"ns:team-a:view"}, ids, "two bindings for one pair must produce one resource")

	// Both bindings must survive in the profile, since deduplication erases them
	// from the resource identity.
	resources, _, err := b.List(context.Background(), nil, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	require.Len(t, resources, 1)
	profile := resources[0].GetProfile().AsMap()
	assert.EqualValues(t, 2, profile[profileKeyBindingCount])
	contributors, ok := profile[profileKeyContributingBindings].([]interface{})
	require.True(t, ok)
	names := []string{}
	for _, c := range contributors {
		names = append(names, c.(map[string]interface{})["name"].(string))
	}
	assert.ElementsMatch(t, []string{"view-alice", "view-bob"}, names)
}

// TestRoleAssignmentNeverMergesClusterAndNamespaceScope guards the other half of
// the key: cluster-wide and namespace-scoped access to the same cluster role are
// different facts.
func TestRoleAssignmentNeverMergesClusterAndNamespaceScope(t *testing.T) {
	b := newRoleAssignmentFixture(
		clusterRole("view"),
		crbFor("view-everywhere", "view", userSubject("alice")),
		rbFor("view-team-a", "team-a", RBACKindClusterRole, "view", userSubject("bob")),
	)

	assert.Equal(t, []string{"cluster:view", "ns:team-a:view"}, listAssignmentIDs(t, b, "sync-1"))
}

// TestRoleAssignmentIDSurvivesNamespaceNamedCluster pins the reason the object ID
// is prefixed by scope type: without it, a namespace literally called "cluster"
// would collide with the cluster-wide pair for the same role.
func TestRoleAssignmentIDSurvivesNamespaceNamedCluster(t *testing.T) {
	b := newRoleAssignmentFixture(
		clusterRole("view"),
		crbFor("view-everywhere", "view", userSubject("alice")),
		rbFor("view-in-ns", "cluster", RBACKindClusterRole, "view", userSubject("bob")),
	)

	ids := listAssignmentIDs(t, b, "sync-1")
	assert.Equal(t, []string{"cluster:view", "ns:cluster:view"}, ids)
	assert.Len(t, ids, 2, "the two scopes must not collide on one ID")
}

// TestRoleAssignmentSkipsUnresolvableRoleRef covers bindings that reference a
// cluster role which does not exist. They are legal and occur on stock clusters;
// emitting one would mint a scope binding whose role_id points at a resource
// this sync never wrote, which C1 drops when mapping the relationship.
func TestRoleAssignmentSkipsUnresolvableRoleRef(t *testing.T) {
	b := newRoleAssignmentFixture(
		clusterRole("view"),
		crbFor("good", "view", userSubject("alice")),
		crbFor("dangling", "no-such-clusterrole", userSubject("ghost")),
	)

	assert.Equal(t, []string{"cluster:view"}, listAssignmentIDs(t, b, "sync-1"))
}

// TestRoleAssignmentIgnoresNamespacedRoles verifies the decided scope: a
// RoleBinding referencing a Role stays in the flat role member entitlement,
// because a Role can only be bound in its own namespace so (role, scope) is 1:1
// with the Role and the sparse form would produce more objects, not fewer.
func TestRoleAssignmentIgnoresNamespacedRoles(t *testing.T) {
	b := newRoleAssignmentFixture(
		clusterRole("view"),
		rbFor("local", "team-a", RBACKindRole, "pod-reader", userSubject("alice")),
		rbFor("shared", "team-a", RBACKindClusterRole, "view", userSubject("bob")),
	)

	assert.Equal(t, []string{"ns:team-a:view"}, listAssignmentIDs(t, b, "sync-1"))
}

// TestRoleAssignmentGrantsDedupeSubjects verifies a subject appearing in two
// bindings for the same pair yields one grant, not a duplicate grant ID.
func TestRoleAssignmentGrantsDedupeSubjects(t *testing.T) {
	b := newRoleAssignmentFixture(
		clusterRole("view"),
		rbFor("first", "team-a", RBACKindClusterRole, "view", userSubject("alice")),
		rbFor("second", "team-a", RBACKindClusterRole, "view", userSubject("alice"), userSubject("bob")),
	)
	ctx := context.Background()

	resources, _, err := b.List(ctx, nil, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	require.Len(t, resources, 1)

	grants, _, err := b.Grants(ctx, resources[0], rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)

	principals := []string{}
	for _, g := range grants {
		principals = append(principals, g.GetPrincipal().GetId().GetResource())
	}
	assert.ElementsMatch(t, []string{"alice", "bob"}, principals,
		"alice appears in both bindings but must be granted once")
}

// TestRoleAssignmentGrantsScopedToNamespace verifies a namespace-scoped pair does
// not pick up subjects bound to the same cluster role in another namespace.
func TestRoleAssignmentGrantsScopedToNamespace(t *testing.T) {
	b := newRoleAssignmentFixture(
		clusterRole("view"),
		rbFor("a", "team-a", RBACKindClusterRole, "view", userSubject("alice")),
		rbFor("b", "team-b", RBACKindClusterRole, "view", userSubject("bob")),
		crbFor("everywhere", "view", userSubject("carol")),
	)
	ctx := context.Background()

	resources, _, err := b.List(ctx, nil, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)

	got := map[string][]string{}
	for _, r := range resources {
		grants, _, err := b.Grants(ctx, r, rs.SyncOpAttrs{SyncID: "sync-1"})
		require.NoError(t, err)
		for _, g := range grants {
			got[r.GetId().GetResource()] = append(got[r.GetId().GetResource()], g.GetPrincipal().GetId().GetResource())
		}
	}

	assert.Equal(t, []string{"alice"}, got["ns:team-a:view"])
	assert.Equal(t, []string{"bob"}, got["ns:team-b:view"])
	assert.Equal(t, []string{"carol"}, got["cluster:view"])
}

// TestRoleAssignmentPagesStably verifies the sorted pair list pages without
// repeating or dropping an entry, since the token is an offset into a list
// rebuilt on every call.
func TestRoleAssignmentPagesStably(t *testing.T) {
	objects := []runtime.Object{clusterRole("view")}
	want := []string{}
	for i := 0; i < 7; i++ {
		ns := fmt.Sprintf("team-%d", i)
		objects = append(objects, rbFor("rb", ns, RBACKindClusterRole, "view", userSubject("alice")))
		want = append(want, fmt.Sprintf("ns:%s:view", ns))
	}
	b := newRoleAssignmentFixture(objects...)
	ctx := context.Background()

	var got []string
	token := ""
	pages := 0
	for {
		resources, results, err := b.List(ctx, nil, rs.SyncOpAttrs{
			SyncID:    "sync-1",
			PageToken: paginationTokenWithSize(token, 3),
		})
		require.NoError(t, err)
		pages++
		for _, r := range resources {
			got = append(got, r.GetId().GetResource())
		}
		if results == nil || results.NextPageToken == "" {
			break
		}
		token = results.NextPageToken
		require.Less(t, pages, 10, "pagination must terminate")
	}

	sort.Strings(want)
	sort.Strings(got)
	assert.Equal(t, want, got)
	assert.Equal(t, 3, pages, "7 pairs at 3 per page")
}

// TestRoleAssignmentResumeSurvivesADeletedPair covers a sync resumed in a fresh
// process while the cluster changed underneath it.
//
// The page token has to be the last pair emitted rather than an index into the
// list. A resumed sync rebuilds that list from current cluster state, so with an
// index, a pair sorting before it disappearing shifts everything down and
// whichever pair lands on the old index is never emitted — silently, because
// nothing errors. Deleting team-a's binding between the two pages here used to
// lose ns:team-c:view entirely.
func TestRoleAssignmentResumeSurvivesADeletedPair(t *testing.T) {
	ctx := context.Background()
	fixture := func(namespaces ...string) *roleAssignmentBuilder {
		objects := []runtime.Object{clusterRole("view")}
		for _, ns := range namespaces {
			objects = append(objects, rbFor("rb", ns, RBACKindClusterRole, "view", userSubject("alice")))
		}
		return newRoleAssignmentFixture(objects...)
	}

	emitted := []string{}
	collect := func(resources []*v2.Resource) {
		for _, r := range resources {
			emitted = append(emitted, r.GetId().GetResource())
		}
	}

	// Page 1, two of four pairs.
	first := fixture("team-a", "team-b", "team-c", "team-d")
	page1, results, err := first.List(ctx, nil, rs.SyncOpAttrs{
		SyncID: "sync-1", PageToken: paginationTokenWithSize("", 2),
	})
	require.NoError(t, err)
	collect(page1)
	require.NotNil(t, results)
	require.NotEmpty(t, results.NextPageToken)

	// The sync resumes in a fresh process — no cached pair list — and team-a's
	// binding is gone, so every remaining pair has shifted down one position.
	resumed := fixture("team-b", "team-c", "team-d")
	for token := results.NextPageToken; ; {
		page, results, err := resumed.List(ctx, nil, rs.SyncOpAttrs{
			SyncID: "sync-1", PageToken: paginationTokenWithSize(token, 2),
		})
		require.NoError(t, err)
		collect(page)
		if results == nil || results.NextPageToken == "" {
			break
		}
		require.NotEqual(t, token, results.NextPageToken, "page token must advance")
		token = results.NextPageToken
	}

	assert.Contains(t, emitted, "ns:team-c:view",
		"the pair after the deleted one must not be skipped by the resume")
	assert.ElementsMatch(t,
		[]string{"ns:team-a:view", "ns:team-b:view", "ns:team-c:view", "ns:team-d:view"},
		emitted)
}

// TestRoleAssignmentRejectsAMalformedPageToken keeps a corrupt token from being
// read as "start from the beginning", which would silently duplicate a page.
func TestRoleAssignmentRejectsAMalformedPageToken(t *testing.T) {
	b := newRoleAssignmentFixture(clusterRole("view"),
		crbFor("view-everywhere", "view", userSubject("alice")))

	_, _, err := b.List(context.Background(), nil, rs.SyncOpAttrs{
		SyncID: "sync-1", PageToken: paginationToken("not-a-cursor"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role assignment page token")
}

// TestClusterRoleSuppressedUnderRoleAssignments verifies the two models are
// mutually exclusive: with the sparse model on, cluster_role must stop emitting
// entitlements and grants or the same access is counted twice.
func TestClusterRoleSuppressedUnderRoleAssignments(t *testing.T) {
	client := fake.NewSimpleClientset(
		clusterRole("view"),
		crbFor("view-everywhere", "view", userSubject("alice")),
	)
	k8s := &Kubernetes{client: client}
	ctx := context.Background()
	resource := &v2.Resource{
		Id:          &v2.ResourceId{ResourceType: ResourceTypeClusterRole.Id, Resource: "view"},
		DisplayName: "view",
	}

	flat := newClusterRoleBuilder(client, k8s, false)
	ents, _, err := flat.Entitlements(ctx, resource, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	assert.NotEmpty(t, ents, "the flat model must still declare cluster role entitlements")
	grants, _, err := flat.Grants(ctx, resource, rs.SyncOpAttrs{SyncID: "sync-1"})
	require.NoError(t, err)
	assert.NotEmpty(t, grants)

	sparse := newClusterRoleBuilder(client, k8s, true)
	ents, _, err = sparse.Entitlements(ctx, resource, rs.SyncOpAttrs{SyncID: "sync-2"})
	require.NoError(t, err)
	assert.Empty(t, ents, "role_assignment expresses this access instead")
	grants, _, err = sparse.Grants(ctx, resource, rs.SyncOpAttrs{SyncID: "sync-2"})
	require.NoError(t, err)
	assert.Empty(t, grants)
}

// TestRoleAssignmentStaticEntitlement verifies exactly one entitlement is
// declared for the whole type; C1 materialises it per resource.
func TestRoleAssignmentStaticEntitlement(t *testing.T) {
	b := newRoleAssignmentFixture(clusterRole("view"))

	ents, _, err := b.StaticEntitlements(context.Background(), rs.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, ents, 1)
	assert.Equal(t, assignedEntitlement, ents[0].GetSlug())

	perResource, _, err := b.Entitlements(context.Background(), &v2.Resource{}, rs.SyncOpAttrs{})
	require.NoError(t, err)
	assert.Empty(t, perResource, "per-resource entitlements would defeat the sparse model")
}

// TestRoleAssignmentPagesByKey covers the second caller of pageBounds. Both this
// builder and api_resource resume from the last key emitted rather than an index,
// and they now share that logic, so each caller needs a multi-page test or a
// change to the shared helper can break one while the other still passes.
func TestRoleAssignmentPagesByKey(t *testing.T) {
	b := newRoleAssignmentFixture(
		clusterRole("view"), clusterRole("edit"), clusterRole("admin"),
		crbFor("view-all", "view", userSubject("alice")),
		crbFor("edit-all", "edit", userSubject("bob")),
		rbFor("admin-team-a", "team-a", RBACKindClusterRole, "admin", userSubject("carol")),
		rbFor("view-team-b", "team-b", RBACKindClusterRole, "view", userSubject("dave")),
	)

	ctx := context.Background()
	var ids []string
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10, "paging must terminate")
		resources, results, err := b.List(ctx, nil, rs.SyncOpAttrs{
			SyncID:    "sync-1",
			PageToken: paginationTokenWithSize(token, 1),
		})
		require.NoError(t, err)
		require.LessOrEqual(t, len(resources), 1, "one per page was requested")
		for _, r := range resources {
			ids = append(ids, r.GetId().GetResource())
		}
		if results == nil || results.NextPageToken == "" {
			break
		}
		token = results.NextPageToken
	}

	// Not sorted: the emission order is part of what this guards. pageBounds
	// resumes from the last key, so an ordering change in the shared helper would
	// show up here as pairs arriving out of assignmentKey.less order.
	assert.Equal(t, []string{"cluster:edit", "cluster:view", "ns:team-a:admin", "ns:team-b:view"}, ids,
		"every pair exactly once, in key order, across single-item pages")
}
