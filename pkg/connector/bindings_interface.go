package connector

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
)

// The syncID parameter on both interfaces scopes the shared binding cache to a
// single sync. Callers inside a resource syncer should pass
// resource.SyncOpAttrs.SyncID; see Kubernetes.loadBindingsCaches for why the
// cache cannot be invalidated from the role builders instead.

// RoleBindingProvider is an interface for retrieving role bindings.
type RoleBindingProvider interface {
	// GetMatchingRoleBindings returns all RoleBindings that reference the specified Role in the given namespace
	GetMatchingRoleBindings(ctx context.Context, syncID, namespace, roleName string) ([]rbacv1.RoleBinding, error)
}

// ClusterRoleBindingProvider is an interface for retrieving cluster role bindings.
type ClusterRoleBindingProvider interface {
	// GetMatchingBindingsForClusterRole returns all RoleBindings and ClusterRoleBindings that reference the specified ClusterRole
	GetMatchingBindingsForClusterRole(ctx context.Context, syncID, clusterRoleName string) ([]rbacv1.RoleBinding, []rbacv1.ClusterRoleBinding, error)
}
