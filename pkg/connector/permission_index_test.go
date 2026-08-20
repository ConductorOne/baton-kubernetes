package connector

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// objectAPIVerbs is what the API server reports for an ordinary namespaced
// resource. Note it carries no impersonate/bind/escalate: those are RBAC-only
// verbs that discovery never reports.
var objectAPIVerbs = []string{
	verbCreate, verbDelete, verbDeleteCollection, verbGet, verbList, verbPatch, verbUpdate, verbWatch,
}

// apiResourceLists is the discovery payload the fake client serves. It is what
// makes cluster-scoped kinds distinguishable from namespaced ones, which is how
// an inert rule is detected.
func apiResourceLists() []*metav1.APIResourceList {
	return []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: pluralPods, Namespaced: true, Verbs: objectAPIVerbs},
				{Name: "pods/exec", Namespaced: true, Verbs: []string{verbCreate, verbGet}},
				{Name: "pods/log", Namespaced: true, Verbs: []string{verbGet}},
				{Name: pluralSecrets, Namespaced: true, Verbs: objectAPIVerbs},
				{Name: pluralConfigMaps, Namespaced: true, Verbs: objectAPIVerbs},
				{Name: pluralServiceAccounts, Namespaced: true, Verbs: objectAPIVerbs},
				{Name: pluralNodes, Namespaced: false, Verbs: objectAPIVerbs},
				{Name: pluralNamespaces, Namespaced: false, Verbs: objectAPIVerbs},
			},
		},
		{
			GroupVersion: "apps/v1",
			APIResources: []metav1.APIResource{
				{Name: pluralDeployments, Namespaced: true, Verbs: objectAPIVerbs},
				{Name: "deployments/scale", Namespaced: true, Verbs: []string{verbGet, verbPatch, verbUpdate}},
			},
		},
	}
}

func rules(rules ...rbacv1.PolicyRule) []rbacv1.PolicyRule { return rules }

func rule(groups, resources, verbs []string, names ...string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{
		APIGroups:     groups,
		Resources:     resources,
		Verbs:         verbs,
		ResourceNames: names,
	}
}

// permissionFixture builds a cluster with one broad ClusterRole bound both
// cluster-wide and in a namespace, plus a namespaced Role, and returns the
// index for the requested membership model.
func permissionFixture(t *testing.T, useRoleAssignments bool) *PermissionIndex {
	t.Helper()

	editor := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "editor"},
		Rules: rules(
			rule([]string{""}, []string{pluralPods, "pods/exec"}, []string{verbCreate, verbGet}),
			rule([]string{""}, []string{pluralNodes}, []string{verbGet}),
			rule(nil, nil, []string{verbGet}),
		),
	}
	editor.Rules[2].NonResourceURLs = []string{"/healthz"}

	appOperator := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "app-operator", Namespace: "team-a"},
		Rules: rules(
			rule([]string{"apps"}, []string{pluralDeployments}, []string{verbGet, verbUpdate}),
			rule([]string{""}, []string{pluralSecrets}, []string{verbGet, verbList}, "app-db-password"),
			// nodes is cluster-scoped, so this rule is inert in a Role.
			rule([]string{""}, []string{pluralNodes}, []string{verbGet, verbList}),
		),
	}

	client := fake.NewSimpleClientset(
		editor,
		appOperator,
		crbFor("editor-everywhere", "editor", userSubject("alice@example.com")),
		rbFor("editor-team-a", "team-a", RBACKindClusterRole, "editor", userSubject("bob@example.com")),
		rbFor("app-operator-team-a", "team-a", RBACKindRole, "app-operator", userSubject("bob@example.com")),
	)
	client.Resources = apiResourceLists()

	k := &Kubernetes{client: client, opts: ConnectorOpts{UseRoleAssignments: useRoleAssignments}}
	index, err := buildPermissionIndex(context.Background(), client, k, "sync-1", useRoleAssignments, false)
	require.NoError(t, err)
	return index
}

func TestPermissionIndexClasses(t *testing.T) {
	index := permissionFixture(t, false)

	ids := make([]string, 0, len(index.Classes()))
	for _, class := range index.Classes() {
		ids = append(ids, class.objectID())
	}

	// Cluster-wide from the ClusterRoleBinding, namespace-scoped from the
	// RoleBinding of the same cluster role, plus the Role's own rules.
	assert.ElementsMatch(t, []string{
		"core:pods@*",
		"core:pods/exec@*",
		"core:nodes@*",
		"_url:/healthz@*",
		"core:pods@team-a",
		"core:pods/exec@team-a",
		"apps:deployments@team-a",
		// The Role can get exactly one Secret, so the target is narrowed to that
		// name. A bare "core:secrets@team-a" would claim it can read them all.
		"core:secrets:app-db-password@team-a",
	}, ids)
}

func TestPermissionIndexDropsInertRules(t *testing.T) {
	index := permissionFixture(t, false)

	for _, class := range index.Classes() {
		if class.scopeType == ResourceTypeNamespace.Id {
			assert.NotEqual(t, pluralNodes, class.resource,
				"a namespace-scoped binding cannot confer access to a cluster-scoped kind")
			assert.NotEqual(t, nonResourceGroup, class.group,
				"a RoleBinding cannot confer non-resource URL access")
		}
	}
	// The cluster role's non-resource URL rule bound in team-a, its nodes rule
	// there, the Role's own nodes rule, and the "list" verb of the Role's
	// resourceNames rule — resourceNames cannot gate a collection request.
	assert.Equal(t, 4, index.inertRules)
}

func TestPermissionIndexVerbsAndPrincipalsFlatModel(t *testing.T) {
	index := permissionFixture(t, false)

	class, ok := index.Class("core:pods@team-a")
	require.True(t, ok)
	assert.Equal(t, []string{verbCreate, verbGet}, index.Verbs(class))

	// Flat model: the cluster role itself is the principal, and the expansion
	// source is its per-namespace membership entitlement.
	assert.Equal(t, []principalRef{{
		resourceType: ResourceTypeClusterRole.Id,
		resourceID:   "editor",
		expandVia:    "team-a:member",
	}}, index.Principals(class, verbCreate))

	clusterClass, ok := index.Class("core:pods@*")
	require.True(t, ok)
	assert.Equal(t, []principalRef{{
		resourceType: ResourceTypeClusterRole.Id,
		resourceID:   "editor",
		expandVia:    clusterScopedMember,
	}}, index.Principals(clusterClass, verbCreate))

	// The namespaced Role is its own principal in both models.
	deployments, ok := index.Class("apps:deployments@team-a")
	require.True(t, ok)
	assert.Equal(t, []principalRef{{
		resourceType: ResourceTypeRole.Id,
		resourceID:   "team-a/app-operator",
		expandVia:    roleMemberEntitlement,
	}}, index.Principals(deployments, verbUpdate))
}

func TestPermissionIndexPrincipalsSparseModel(t *testing.T) {
	index := permissionFixture(t, true)

	nsClass, ok := index.Class("core:pods@team-a")
	require.True(t, ok)
	assert.Equal(t, []principalRef{{
		resourceType: ResourceTypeRoleAssignment.Id,
		resourceID:   "ns:team-a:editor",
		expandVia:    assignedEntitlement,
	}}, index.Principals(nsClass, verbGet))

	clusterClass, ok := index.Class("core:pods@*")
	require.True(t, ok)
	assert.Equal(t, []principalRef{{
		resourceType: ResourceTypeRoleAssignment.Id,
		resourceID:   "cluster:editor",
		expandVia:    assignedEntitlement,
	}}, index.Principals(clusterClass, verbGet))
}

// TestPermissionIndexNamedRuleDoesNotWidenTheClass pins the fidelity rule: a
// role that can read one Secret must never appear to hold "get secrets" for the
// namespace.
func TestPermissionIndexNamedRuleDoesNotWidenTheClass(t *testing.T) {
	index := permissionFixture(t, false)

	_, ok := index.Class("core:secrets@team-a")
	assert.False(t, ok, "a resourceNames rule must not mint the unrestricted target")

	narrowed, ok := index.Class("core:secrets:app-db-password@team-a")
	require.True(t, ok)
	assert.Equal(t, []string{verbGet}, index.Verbs(narrowed),
		"list is dropped: a collection request carries no name for resourceNames to match")
	assert.Equal(t, `secrets "app-db-password" in team-a`, narrowed.displayName())
}

func TestPermissionIndexNamedObjects(t *testing.T) {
	index := permissionFixture(t, false)

	verbs := index.namedVerbs(namedObject{
		resourceType: ResourceTypeSecret.Id,
		objectID:     "team-a/app-db-password",
	})
	require.Len(t, verbs, 1, "only name-known verbs are gated by resourceNames")
	require.Contains(t, verbs, verbGet)
	assert.NotContains(t, verbs, verbList, "resourceNames never authorizes list")

	assert.Equal(t, []principalRef{{
		resourceType: ResourceTypeRole.Id,
		resourceID:   "team-a/app-operator",
		expandVia:    roleMemberEntitlement,
	}}, verbs[verbGet])
}

func TestPermissionIndexClusterWideNamedObjectHasNoInstanceEdge(t *testing.T) {
	// A namespaced kind named by a cluster-wide binding means that name in every
	// namespace, so no single object is the target.
	reader := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "reader"},
		Rules:      rules(rule([]string{""}, []string{pluralSecrets}, []string{verbGet}, "shared")),
	}
	client := fake.NewSimpleClientset(reader, crbFor("reader-all", "reader", userSubject("alice@example.com")))
	client.Resources = apiResourceLists()

	k := &Kubernetes{client: client, opts: ConnectorOpts{}}
	index, err := buildPermissionIndex(context.Background(), client, k, "sync-1", false, false)
	require.NoError(t, err)

	assert.Empty(t, index.named)
	_, ok := index.Class("core:secrets:shared@*")
	assert.True(t, ok, "the narrowed target still records the permission")
}

func TestObjectEntitlementsAndGrantsForNamedObject(t *testing.T) {
	index := permissionFixture(t, false)
	resolver := &permissionResolver{provider: stubProvider{index: index}}

	secret, err := rs.NewResource("app-db-password", ResourceTypeSecret, "team-a/app-db-password")
	require.NoError(t, err)

	// The entitlement is declared for the type, not for this object...
	entitlements := staticObjectEntitlements(ResourceTypeSecret)
	slugs := make([]string, 0, len(entitlements))
	for _, ent := range entitlements {
		slugs = append(slugs, ent.GetSlug())
	}
	assert.Contains(t, slugs, verbGet)

	// ...while the grant is what makes it specific to this one.
	grants, err := objectGrants(context.Background(), resolver, rs.SyncOpAttrs{SyncID: "sync-1"}, ResourceTypeSecret, secret)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, ResourceTypeRole.Id, grants[0].GetPrincipal().GetId().GetResourceType())

	expandable := &v2.GrantExpandable{}
	annos := annotations.Annotations(grants[0].GetAnnotations())
	ok, err := annos.Pick(expandable)
	require.NoError(t, err)
	require.True(t, ok, "permission grants must be expandable so subjects inherit them")
	assert.Equal(t, []string{"role:team-a/app-operator:member"}, expandable.GetEntitlementIds())
}

// TestNilResolverEmitsNothing pins the contract that keeps object resources pure
// inventory while granular permissions are off.
func TestNilResolverEmitsNothing(t *testing.T) {
	pod, err := rs.NewResource("api-server", ResourceTypePod, "team-a/api-server")
	require.NoError(t, err)

	// The declaration needs no resolver at all: it is a fixed capability list.
	assert.NotEmpty(t, staticObjectEntitlements(ResourceTypePod))

	grants, err := objectGrants(context.Background(), nil, rs.SyncOpAttrs{}, ResourceTypePod, pod)
	require.NoError(t, err)
	assert.Empty(t, grants)
}

type stubProvider struct {
	index *PermissionIndex
}

func (s stubProvider) PermissionIndex(_ context.Context, _ string) (*PermissionIndex, error) {
	return s.index, nil
}

// TestObjectPermissionsFromUnrestrictedRules covers the object half of the model:
// an object picks up the rules reaching its type in its namespace and
// cluster-wide, without any rule having to name it.
func TestObjectPermissionsFromUnrestrictedRules(t *testing.T) {
	resolver := &permissionResolver{provider: stubProvider{index: permissionFixture(t, false)}}

	namespaceID, err := NamespaceResourceID("team-a")
	require.NoError(t, err)
	pod, err := rs.NewResource("api-server", ResourceTypePod, "team-a/api-server",
		rs.WithParentResourceID(namespaceID))
	require.NoError(t, err)

	permissions, err := resolver.objectPermissions(context.Background(), "sync-1", ResourceTypePod, pod)
	require.NoError(t, err)

	slugs := sortedSlugs(permissions)
	// "get" from the pods rule; the pods/exec rule contributes both its verbs,
	// named after the subresource so "create" cannot be read as creating the pod.
	// "create" on pods itself is absent: creating an object addresses no object.
	assert.Equal(t, []string{"create:exec", verbGet, "get:exec"}, slugs)
	assert.Equal(t, "create exec", slugLabel("create:exec"))

	// Both the cluster-wide and the namespace binding of the same cluster role
	// reach this pod, and they are distinct principals.
	assert.ElementsMatch(t, []principalRef{
		{resourceType: ResourceTypeClusterRole.Id, resourceID: "editor", expandVia: clusterScopedMember},
		{resourceType: ResourceTypeClusterRole.Id, resourceID: "editor", expandVia: "team-a:member"},
	}, permissions[verbGet])
}

// TestObjectPermissionsScopeIsolation pins that a rule bound in one namespace
// does not reach an object in another.
func TestObjectPermissionsScopeIsolation(t *testing.T) {
	resolver := &permissionResolver{provider: stubProvider{index: permissionFixture(t, false)}}

	namespaceID, err := NamespaceResourceID("team-b")
	require.NoError(t, err)
	pod, err := rs.NewResource("web", ResourceTypePod, "team-b/web", rs.WithParentResourceID(namespaceID))
	require.NoError(t, err)

	permissions, err := resolver.objectPermissions(context.Background(), "sync-1", ResourceTypePod, pod)
	require.NoError(t, err)

	// Only the cluster-wide binding reaches team-b.
	for slug, principals := range permissions {
		for _, principal := range principals {
			assert.Equal(t, clusterScopedMember, principal.expandVia,
				"slug %s leaked a namespace-scoped principal into team-b", slug)
		}
	}
}

// TestObjectPermissionsClusterScopedKind pins that a cluster-scoped object reads
// only cluster-wide rules — a namespace has no say over a node.
func TestObjectPermissionsClusterScopedKind(t *testing.T) {
	resolver := &permissionResolver{provider: stubProvider{index: permissionFixture(t, false)}}

	node, err := rs.NewResource("worker-1", ResourceTypeNode, "worker-1")
	require.NoError(t, err)

	permissions, err := resolver.objectPermissions(context.Background(), "sync-1", ResourceTypeNode, node)
	require.NoError(t, err)
	assert.Equal(t, []string{verbGet}, sortedSlugs(permissions))
	assert.Equal(t, []principalRef{{
		resourceType: ResourceTypeClusterRole.Id,
		resourceID:   "editor",
		expandVia:    clusterScopedMember,
	}}, permissions[verbGet])
}

// TestPodsSkipSyncAnomalyDetection pins the annotation that keeps a rollout from
// reading as a data drop.
func TestPodsSkipSyncAnomalyDetection(t *testing.T) {
	annos := annotations.Annotations(ResourceTypePod.GetAnnotations())
	assert.True(t, annos.Contains(&v2.SkipSyncAnomalyDetection{}))
	assert.True(t, annos.Contains(&v2.OptInRequired{}))

	// Only pods: a namespace or secret disappearing is worth flagging.
	for _, rt := range []*v2.ResourceType{ResourceTypeSecret, ResourceTypeConfigMap, ResourceTypeNamespace} {
		other := annotations.Annotations(rt.GetAnnotations())
		assert.False(t, other.Contains(&v2.SkipSyncAnomalyDetection{}), rt.GetId())
	}
}

// controlPlaneFixture binds a system: cluster role cluster-wide, the way every
// stock cluster does for its controllers.
func controlPlaneFixture(t *testing.T, includeControlPlane bool) *PermissionIndex {
	t.Helper()

	controller := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:controller:namespace-controller"},
		Rules:      rules(rule([]string{""}, []string{pluralSecrets}, []string{verbGet, verbDelete})),
	}
	client := fake.NewSimpleClientset(controller,
		crbFor("namespace-controller", "system:controller:namespace-controller",
			rbacv1.Subject{Kind: SubjectKindServiceAccount, Name: "namespace-controller", Namespace: "kube-system"}))
	client.Resources = apiResourceLists()

	k := &Kubernetes{client: client, opts: ConnectorOpts{}}
	index, err := buildPermissionIndex(context.Background(), client, k, "sync-1", false, includeControlPlane)
	require.NoError(t, err)
	return index
}

// TestControlPlanePermissionsSkippedOnObjects pins the default: what the control
// plane can do is reported once per API resource, not once per object.
func TestControlPlanePermissionsSkippedOnObjects(t *testing.T) {
	index := controlPlaneFixture(t, false)

	// The API resource target keeps the whole picture.
	class, ok := index.Class("core:secrets@*")
	require.True(t, ok)
	assert.Equal(t, []string{verbDelete, verbGet}, index.Verbs(class))

	// The object layer drops it.
	assert.Empty(t, index.objectPermissions(objectScope{
		resourceType: ResourceTypeSecret.Id,
		scopeType:    ResourceTypeCluster.Id,
		scopeID:      clusterScopeID,
	}))
}

// TestControlPlanePermissionsIncludedWhenAsked pins the opt-out.
func TestControlPlanePermissionsIncludedWhenAsked(t *testing.T) {
	index := controlPlaneFixture(t, true)

	permissions := index.objectPermissions(objectScope{
		resourceType: ResourceTypeSecret.Id,
		scopeType:    ResourceTypeCluster.Id,
		scopeID:      clusterScopeID,
	})
	assert.Equal(t, []string{verbDelete, verbGet}, sortedSlugs(permissions))
}

func TestIsControlPlaneRole(t *testing.T) {
	assert.True(t, isControlPlaneRole("system:controller:namespace-controller"))
	assert.True(t, isControlPlaneRole("system:node"))
	assert.False(t, isControlPlaneRole("edit"))
	// A prefix match, so a tenant's own role is never mistaken for the control
	// plane just because the word appears in it.
	assert.False(t, isControlPlaneRole("acme-system:reader"))
}

// TestObjectPermissionsAreFixedNotDerived pins the contract that an object's
// entitlements are a capability set, not an observation: a pod declares delete
// even though nothing in this fixture grants it.
func TestObjectPermissionsAreFixedNotDerived(t *testing.T) {
	index := permissionFixture(t, false)
	resolver := &permissionResolver{provider: stubProvider{index: index}}

	pod, err := rs.NewResource("api-server", ResourceTypePod, "team-a/api-server")
	require.NoError(t, err)
	granted, err := resolver.objectPermissions(context.Background(), "sync-1", ResourceTypePod, pod)
	require.NoError(t, err)
	assert.NotContains(t, granted, verbDelete, "nothing in the fixture confers delete on a pod")

	slugs := make([]string, 0)
	for _, ent := range staticObjectEntitlements(ResourceTypePod) {
		slugs = append(slugs, ent.GetSlug())
		assert.Nil(t, ent.GetResource(), "a static template names no resource; the syncer fans it out")
	}
	assert.Contains(t, slugs, verbDelete,
		"the entitlement exists regardless, so nothing referencing it churns when a role changes")
	assert.Contains(t, slugs, "create:exec")
	assert.Contains(t, slugs, verbAll)
}

// TestObjectPermissionsExcludeCollectionVerbs pins that the fixed set is only the
// object-addressable half — "list pods" is not a permission on one pod.
func TestObjectPermissionsExcludeCollectionVerbs(t *testing.T) {
	slugs := objectPermissionSets[ResourceTypeSecret.Id]
	assert.Equal(t, []string{verbAll, verbDelete, verbGet, verbPatch, verbUpdate}, slugs)
	for _, collectionVerb := range []string{verbList, verbWatch, verbCreate, verbDeleteCollection} {
		assert.NotContains(t, slugs, collectionVerb)
	}
}

// TestObjectPermissionsIncludeRBACOnlyVerbs pins impersonate, which the cluster's
// discovery document never reports because it authorizes an action rather than
// naming an endpoint.
func TestObjectPermissionsIncludeRBACOnlyVerbs(t *testing.T) {
	assert.Contains(t, objectPermissionSets[ResourceTypeServiceAccount.Id], verbImpersonate)
	assert.Contains(t, objectPermissionSets[ResourceTypeServiceAccount.Id], "create:token")
}

// TestUndeclaredPermissionIsDropped pins the clamp: a grant can never reference an
// entitlement the type does not declare, because nothing would have created it.
func TestUndeclaredPermissionIsDropped(t *testing.T) {
	// pods/madeupsubresource does not exist, so this rule authorizes nothing.
	exotic := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "widget-operator"},
		Rules:      rules(rule([]string{""}, []string{"pods/madeupsubresource"}, []string{verbCreate})),
	}
	client := fake.NewSimpleClientset(exotic,
		crbFor("widget-operator", "widget-operator", userSubject("alice@example.com")))
	client.Resources = apiResourceLists()

	k := &Kubernetes{client: client, opts: ConnectorOpts{}}
	index, err := buildPermissionIndex(context.Background(), client, k, "sync-1", false, false)
	require.NoError(t, err)

	pod, err := rs.NewResource("api-server", ResourceTypePod, "team-a/api-server")
	require.NoError(t, err)
	resolver := &permissionResolver{provider: stubProvider{index: index}}
	granted, err := resolver.objectPermissions(context.Background(), "sync-1", ResourceTypePod, pod)
	require.NoError(t, err)
	assert.NotContains(t, granted, "create:madeupsubresource")

	// The class target still records what the rule says, without claiming it
	// reaches any object.
	_, ok := index.Class("core:pods/madeupsubresource@*")
	assert.True(t, ok)
}
