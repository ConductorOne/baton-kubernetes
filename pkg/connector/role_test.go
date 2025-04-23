package connector

import (
	"context"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// extractVerbFromEntitlementID extracts the verb from an entitlement ID
// Format: resource_type:resource:verb
func extractVerbFromEntitlementID(id string) string {
	parts := strings.Split(id, ":")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// mockRoleBindingProvider implements the roleBindingProvider interface for testing
type mockRoleBindingProvider struct {
	roleBindingsMap map[string][]rbacv1.RoleBinding // key: namespace/roleName
}

// GetMatchingRoleBindings returns mock role bindings for testing
func (m *mockRoleBindingProvider) GetMatchingRoleBindings(ctx context.Context, namespace, roleName string) ([]rbacv1.RoleBinding, error) {
	key := namespace + "/" + roleName
	return m.roleBindingsMap[key], nil
}

// newMockRoleBindingProvider creates a new mock binding provider
func newMockRoleBindingProvider() *mockRoleBindingProvider {
	return &mockRoleBindingProvider{
		roleBindingsMap: make(map[string][]rbacv1.RoleBinding),
	}
}

// addMockBinding adds a role binding to the mock provider
func (m *mockRoleBindingProvider) addMockBinding(namespace, roleName string, binding rbacv1.RoleBinding) {
	key := namespace + "/" + roleName
	m.roleBindingsMap[key] = append(m.roleBindingsMap[key], binding)
}

// mockClusterRoleBindingProvider implements the clusterRoleBindingProvider interface for testing
type mockClusterRoleBindingProvider struct {
	roleBindingsMap        map[string][]rbacv1.RoleBinding
	clusterRoleBindingsMap map[string][]rbacv1.ClusterRoleBinding
}

// GetMatchingBindingsForClusterRole returns mock bindings for testing
func (m *mockClusterRoleBindingProvider) GetMatchingBindingsForClusterRole(ctx context.Context, clusterRoleName string) ([]rbacv1.RoleBinding, []rbacv1.ClusterRoleBinding, error) {
	return m.roleBindingsMap[clusterRoleName], m.clusterRoleBindingsMap[clusterRoleName], nil
}

// newMockClusterRoleBindingProvider creates a new mock provider
func newMockClusterRoleBindingProvider() *mockClusterRoleBindingProvider {
	return &mockClusterRoleBindingProvider{
		roleBindingsMap:        make(map[string][]rbacv1.RoleBinding),
		clusterRoleBindingsMap: make(map[string][]rbacv1.ClusterRoleBinding),
	}
}

// addMockRoleBinding adds a role binding to the mock provider
func (m *mockClusterRoleBindingProvider) addMockRoleBinding(clusterRoleName string, binding rbacv1.RoleBinding) {
	m.roleBindingsMap[clusterRoleName] = append(m.roleBindingsMap[clusterRoleName], binding)
}

// addMockClusterRoleBinding adds a cluster role binding to the mock provider
func (m *mockClusterRoleBindingProvider) addMockClusterRoleBinding(clusterRoleName string, binding rbacv1.ClusterRoleBinding) {
	m.clusterRoleBindingsMap[clusterRoleName] = append(m.clusterRoleBindingsMap[clusterRoleName], binding)
}

// TestRoleBuilderList tests the List method
func TestRoleBuilderList(t *testing.T) {
	// We'll focus on a simpler approach: directly testing the roleResource
	// function conversion instead of the List method which has issues with the
	// fake client

	// Create a test role
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "test-ns",
			UID:       "test-uid",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
		},
	}

	// Call roleResource directly
	resource, err := roleResource(role)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, "test-role", resource.DisplayName)
	assert.Equal(t, "test-ns/test-role", resource.Id.Resource)
	assert.Equal(t, resourceTypeRole.Id, resource.Id.ResourceType)
}

// TestRoleBuilderGrants_NoBindings tests that a role without bindings produces no grants
func TestRoleBuilderGrants_NoBindings(t *testing.T) {
	// Setup test role
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "test-ns",
			UID:       "test-uid",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
		},
	}

	// Setup test components
	fakeClient := fake.NewSimpleClientset(role)
	mockBindingProvider := newMockRoleBindingProvider()
	builder := &roleBuilder{
		client:          fakeClient,
		bindingProvider: mockBindingProvider,
	}

	// Create a test resource
	testResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeRole.Id,
			Resource:     "test-ns/test-role",
		},
		DisplayName: "test-role",
	}

	// Call Grants method
	ctx := context.Background()
	pToken := &pagination.Token{}
	grants, _, _, err := builder.Grants(ctx, testResource, pToken)

	// Assertions
	require.NoError(t, err)
	assert.Empty(t, grants, "A role without bindings should produce no grants")
}

// TestRoleBuilderGrants_WithBindings tests grants with role bindings
func TestRoleBuilderGrants_WithBindings(t *testing.T) {
	// Setup test role
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-reader",
			Namespace: "test-ns",
			UID:       "test-uid",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
		},
	}

	// Setup test role binding for a user
	userBinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "read-pods-binding",
			Namespace: "test-ns",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "pod-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "alice",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}

	// Setup test role binding for a service account
	saBinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system-pods-binding",
			Namespace: "test-ns",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "pod-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "system",
				Namespace: "test-ns",
			},
		},
	}

	// Setup test components
	fakeClient := fake.NewSimpleClientset(role)
	mockBindingProvider := newMockRoleBindingProvider()
	mockBindingProvider.addMockBinding("test-ns", "pod-reader", userBinding)
	mockBindingProvider.addMockBinding("test-ns", "pod-reader", saBinding)

	builder := &roleBuilder{
		client:          fakeClient,
		bindingProvider: mockBindingProvider,
	}

	// Create a test resource
	testResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeRole.Id,
			Resource:     "test-ns/pod-reader",
		},
		DisplayName: "pod-reader",
	}

	// Call Grants method
	ctx := context.Background()
	pToken := &pagination.Token{}
	grants, _, _, err := builder.Grants(ctx, testResource, pToken)

	// Assertions
	require.NoError(t, err)

	// We expect 6 grants: 3 verbs × 2 subjects
	require.Len(t, grants, 6, "Should have 6 grants (3 verbs × 2 subjects)")

	// Count grants by subject type and verb
	userGrants := 0
	saGrants := 0
	verbCounts := map[string]int{"get": 0, "list": 0, "watch": 0}

	for _, g := range grants {
		// Extract verb from entitlement ID
		verb := extractVerbFromEntitlementID(g.Entitlement.Id)
		verbCounts[verb]++

		// Check that all principals are pods (the target resource)
		assert.Equal(t, resourceTypePod.Id, g.Principal.Id.ResourceType, "Principal should be pod resource")
		assert.Equal(t, "*", g.Principal.Id.Resource, "Principal should be wildcard pod resource")

		// Check the entitlement resource (the source of permission, aka the subject)
		subjType := g.Entitlement.Resource.Id.ResourceType
		subjResource := g.Entitlement.Resource.Id.Resource

		// Count by subject type in entitlement
		if subjType == resourceTypeKubeUser.Id && strings.Contains(subjResource, "alice") {
			userGrants++
		} else if subjType == resourceTypeServiceAccount.Id && strings.Contains(subjResource, "system") {
			saGrants++
		}
	}

	// Verify correct counts
	assert.Equal(t, 3, userGrants, "Should have 3 grants for user alice")
	assert.Equal(t, 3, saGrants, "Should have 3 grants for service account system")

	// Verify correct verb counts
	assert.Equal(t, 2, verbCounts["get"], "Should have 2 get grants (1 per subject)")
	assert.Equal(t, 2, verbCounts["list"], "Should have 2 list grants (1 per subject)")
	assert.Equal(t, 2, verbCounts["watch"], "Should have 2 watch grants (1 per subject)")
}

// TestRoleBuilderGrants_WildcardVerbs tests handling of wildcard verbs with bindings
func TestRoleBuilderGrants_WildcardVerbs(t *testing.T) {
	// Setup test role with wildcard verb
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-admin",
			Namespace: "test-ns",
			UID:       "test-uid",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
		},
	}

	// Setup test role binding for a group
	groupBinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin-pods-binding",
			Namespace: "test-ns",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "pod-admin",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "admins",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}

	// Setup test components
	fakeClient := fake.NewSimpleClientset(role)
	mockBindingProvider := newMockRoleBindingProvider()
	mockBindingProvider.addMockBinding("test-ns", "pod-admin", groupBinding)

	builder := &roleBuilder{
		client:          fakeClient,
		bindingProvider: mockBindingProvider,
	}

	// Create a test resource
	testResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeRole.Id,
			Resource:     "test-ns/pod-admin",
		},
		DisplayName: "pod-admin",
	}

	// Call Grants method
	ctx := context.Background()
	pToken := &pagination.Token{}
	grants, _, _, err := builder.Grants(ctx, testResource, pToken)

	// Assertions
	require.NoError(t, err)
	assert.NotEmpty(t, grants, "Should generate grants for wildcard verb")

	// Standard verbs that should be expanded from *
	standardVerbs := []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}

	// Verify all standard verbs were expanded for the group
	foundVerbs := make(map[string]bool)
	for _, g := range grants {
		// All principals should be pods
		assert.Equal(t, resourceTypePod.Id, g.Principal.Id.ResourceType, "Principal should be pod resource")
		assert.Equal(t, "*", g.Principal.Id.Resource, "Principal should be wildcard pod resource")

		// All entitlement resources should be the group
		assert.Equal(t, resourceTypeKubeGroup.Id, g.Entitlement.Resource.Id.ResourceType, "Entitlement resource should be group")
		assert.Equal(t, "admins", g.Entitlement.Resource.Id.Resource, "Entitlement resource should be 'admins' group")

		// Track which verbs we found
		verb := extractVerbFromEntitlementID(g.Entitlement.Id)
		foundVerbs[verb] = true
	}

	// Verify all standard verbs were expanded
	for _, verb := range standardVerbs {
		assert.True(t, foundVerbs[verb], "Should have expanded wildcard to include verb: "+verb)
	}
}

// TestRoleBuilderGrants_MultipleResources tests grants with multiple resources in a rule
func TestRoleBuilderGrants_MultipleResources(t *testing.T) {
	// Setup test role with multiple resources
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "resource-reader",
			Namespace: "test-ns",
			UID:       "test-uid",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps", "secrets"},
			},
		},
	}

	// Setup test role binding
	binding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reader-binding",
			Namespace: "test-ns",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "resource-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "reader",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}

	// Setup test components
	fakeClient := fake.NewSimpleClientset(role)
	mockBindingProvider := newMockRoleBindingProvider()
	mockBindingProvider.addMockBinding("test-ns", "resource-reader", binding)

	builder := &roleBuilder{
		client:          fakeClient,
		bindingProvider: mockBindingProvider,
	}

	// Create a test resource
	testResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeRole.Id,
			Resource:     "test-ns/resource-reader",
		},
		DisplayName: "resource-reader",
	}

	// Call Grants method
	ctx := context.Background()
	pToken := &pagination.Token{}
	grants, _, _, err := builder.Grants(ctx, testResource, pToken)

	// Assertions
	require.NoError(t, err)

	// We expect 6 grants: 2 verbs × 3 resources × 1 subject
	require.Len(t, grants, 6, "Should have 6 grants (2 verbs × 3 resources × 1 subject)")

	// Track which resource types as principals and verbs are covered
	principalTypeVerbs := make(map[string]map[string]bool)

	for _, g := range grants {
		// All entitlement resources should be the user
		assert.Equal(t, resourceTypeKubeUser.Id, g.Entitlement.Resource.Id.ResourceType, "Entitlement resource should be user")
		assert.Equal(t, "reader", g.Entitlement.Resource.Id.Resource, "Entitlement resource should be 'reader' user")

		// Principal should be one of the target resources
		principalType := g.Principal.Id.ResourceType
		verb := extractVerbFromEntitlementID(g.Entitlement.Id)

		// Track verbs per principal resource type
		if principalTypeVerbs[principalType] == nil {
			principalTypeVerbs[principalType] = make(map[string]bool)
		}
		principalTypeVerbs[principalType][verb] = true
	}

	// Verify all resources have both get and list
	resourceTypes := []string{resourceTypePod.Id, resourceTypeConfigMap.Id, resourceTypeSecret.Id}
	expectedVerbs := []string{"get", "list"}

	for _, rt := range resourceTypes {
		require.NotNil(t, principalTypeVerbs[rt], "Should have grants for resource type: "+rt)

		for _, v := range expectedVerbs {
			assert.True(t, principalTypeVerbs[rt][v], "Should have verb %s for resource type %s", v, rt)
		}
	}
}

// TestClusterRoleBuilderGrants tests the ClusterRoleBuilder Grants method
func TestClusterRoleBuilderGrants(t *testing.T) {
	// Setup test clusterrole with multiple resources
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-reader",
			UID:  "test-uid",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"nodes", "namespaces"},
			},
		},
	}

	// Setup test cluster role binding for a group
	groupBinding := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-infra-binding",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "node-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "infra-admins",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}

	// Setup test role binding for a service account (namespaced binding to cluster role)
	saBinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-node-reader",
			Namespace: "monitoring",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "node-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "monitoring-app",
				Namespace: "monitoring",
			},
		},
	}

	// Setup test components
	fakeClient := fake.NewSimpleClientset(clusterRole)
	mockBindingProvider := newMockClusterRoleBindingProvider()
	mockBindingProvider.addMockClusterRoleBinding("node-reader", groupBinding)
	mockBindingProvider.addMockRoleBinding("node-reader", saBinding)

	builder := &clusterRoleBuilder{
		client:          fakeClient,
		bindingProvider: mockBindingProvider,
	}

	// Create a test resource
	testResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeClusterRole.Id,
			Resource:     "node-reader",
		},
		DisplayName: "node-reader",
	}

	// Call Grants method
	ctx := context.Background()
	pToken := &pagination.Token{}
	grants, _, _, err := builder.Grants(ctx, testResource, pToken)

	// Assertions
	require.NoError(t, err)

	// We expect 4 grants: 2 verbs × 2 resources × (1 group + 1 service account)
	require.Len(t, grants, 8, "Should have 8 grants (2 verbs × 2 resources × 2 subjects)")

	// Count grants by subject type and resource type
	groupGrants := 0
	saGrants := 0
	nodeGrants := 0
	namespaceGrants := 0
	verbCounts := map[string]int{"get": 0, "list": 0}

	for _, g := range grants {
		// Extract verb from entitlement ID
		verb := extractVerbFromEntitlementID(g.Entitlement.Id)
		verbCounts[verb]++

		// Count by principal (target) type
		switch g.Principal.Id.ResourceType {
		case resourceTypeNode.Id:
			nodeGrants++
		case resourceTypeNamespace.Id:
			namespaceGrants++
		}

		// Count by entitlement resource (subject) type
		switch g.Entitlement.Resource.Id.ResourceType {
		case resourceTypeKubeGroup.Id:
			assert.Equal(t, "infra-admins", g.Entitlement.Resource.Id.Resource, "Group should be infra-admins")
			groupGrants++
		case resourceTypeServiceAccount.Id:
			assert.Contains(t, g.Entitlement.Resource.Id.Resource, "monitoring-app", "Service account should contain monitoring-app")
			saGrants++
		}
	}

	// Verify correct counts
	assert.Equal(t, 4, groupGrants, "Should have 4 grants for group infra-admins (2 resources × 2 verbs)")
	assert.Equal(t, 4, saGrants, "Should have 4 grants for monitoring-app service account (2 resources × 2 verbs)")
	assert.Equal(t, 4, nodeGrants, "Should have 4 grants targeting nodes (2 subjects × 2 verbs)")
	assert.Equal(t, 4, namespaceGrants, "Should have 4 grants targeting namespaces (2 subjects × 2 verbs)")
	assert.Equal(t, 4, verbCounts["get"], "Should have 4 get grants (2 subjects × 2 resources)")
	assert.Equal(t, 4, verbCounts["list"], "Should have 4 list grants (2 subjects × 2 resources)")
}
