package connector

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
)

// RoleBindingProvider is an interface for retrieving role bindings.
type RoleBindingProvider interface {
	// GetMatchingRoleBindings returns all RoleBindings that reference the specified Role in the given namespace
	GetMatchingRoleBindings(ctx context.Context, namespace, roleName string) ([]rbacv1.RoleBinding, error)
}

// ClusterRoleBindingProvider is an interface for retrieving cluster role bindings.
type ClusterRoleBindingProvider interface {
	// GetMatchingBindingsForClusterRole returns all RoleBindings and ClusterRoleBindings that reference the specified ClusterRole
	GetMatchingBindingsForClusterRole(ctx context.Context, clusterRoleName string) ([]rbacv1.RoleBinding, []rbacv1.ClusterRoleBinding, error)
}
