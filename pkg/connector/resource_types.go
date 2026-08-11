package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

// optInAnnotations marks a resource type as excluded from the default sync;
// the platform requires an explicit opt-in (and the CLI an explicit
// --sync-resource-types selection) to include it.
func optInAnnotations() annotations.Annotations {
	return annotations.New(&v2.OptInRequired{})
}

// roleAssignmentAnnotations marks the sparse cluster role assignment type.
// SkipEntitlements is what makes it sparse: the type declares one shared
// entitlement through StaticEntitlements rather than one per resource.
func roleAssignmentAnnotations() annotations.Annotations {
	return annotations.New(&v2.OptInRequired{}, &v2.SkipEntitlements{})
}

// Resource type definitions.
var (
	ResourceTypeNamespace      = &v2.ResourceType{Id: profileKeyNamespace, DisplayName: "Namespace"}
	ResourceTypeServiceAccount = &v2.ResourceType{Id: "service_account", DisplayName: "Service Account", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	ResourceTypeRole           = &v2.ResourceType{Id: "role", DisplayName: RBACKindRole, Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE}}
	ResourceTypeClusterRole    = &v2.ResourceType{Id: "cluster_role", DisplayName: "Cluster Role", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE}}
	ResourceTypeSecret         = &v2.ResourceType{Id: "secret", DisplayName: "Secret", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET}, Annotations: optInAnnotations()}
	ResourceTypeConfigMap      = &v2.ResourceType{Id: "configmap", DisplayName: "Config Map", Annotations: optInAnnotations()}
	ResourceTypeNode           = &v2.ResourceType{Id: "node", DisplayName: "Node", Annotations: optInAnnotations()}
	ResourceTypePod            = &v2.ResourceType{Id: "pod", DisplayName: "Pod", Annotations: optInAnnotations()}
	ResourceTypeDeployment     = &v2.ResourceType{Id: "deployment", DisplayName: "Deployment", Annotations: optInAnnotations()}
	ResourceTypeStatefulSet    = &v2.ResourceType{Id: "statefulset", DisplayName: "Stateful Set", Annotations: optInAnnotations()}
	ResourceTypeDaemonSet      = &v2.ResourceType{Id: "daemonset", DisplayName: "Daemon Set", Annotations: optInAnnotations()}
	ResourceTypeKubeUser       = &v2.ResourceType{Id: "kube_user", DisplayName: "Kubernetes User", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	ResourceTypeKubeGroup      = &v2.ResourceType{Id: "kube_group", DisplayName: "Kubernetes Group", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}}
	// ResourceTypeCluster is a singleton standing for the cluster itself. It
	// exists so a ClusterRoleBinding has a scope resource to point at: C1 drops a
	// role-scope-binding relationship whose scope resource was never synced.
	// It carries no trait, deliberately — a role or group trait here would count
	// the cluster as classic access in C1's access-model derivation.
	ResourceTypeCluster = &v2.ResourceType{
		Id:          "cluster",
		DisplayName: "Cluster",
		Annotations: annotations.New(&v2.OptInRequired{}, &v2.SkipEntitlementsAndGrants{}),
	}
	// ResourceTypeRoleAssignment is one (cluster role, scope) pair that actually
	// has a binding. Named neutrally so namespaced Roles can fold in later
	// without a new type or a second platform opt-in.
	ResourceTypeRoleAssignment = &v2.ResourceType{
		Id:          "role_assignment",
		DisplayName: "Role Assignment",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SCOPE_BINDING},
		Annotations: roleAssignmentAnnotations(),
	}
	ResourceTypeBinding = &v2.ResourceType{Id: "binding", DisplayName: "Binding", Description: "Internal type for processing RBAC bindings"}
	ResourceTypeUser    = &v2.ResourceType{Id: "user", DisplayName: SubjectTypeUser, Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	ResourceTypeGroup   = &v2.ResourceType{Id: "group", DisplayName: SubjectTypeGroup, Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}}
)

// SparseResourceTypeIDs lists the types belonging to the sparse model, which
// replaces the cluster_role entitlement and grant surface rather than adding to
// it.
//
// They are registered like every other type, whatever --use-role-assignments
// says; the flag decides only whether their builders emit anything. Registering
// them conditionally would fail the sync outright for a tenant who selects
// role_assignment while the flag is off, since the SDK validates the selection
// against the registered types.
var SparseResourceTypeIDs = []string{
	ResourceTypeCluster.Id,
	ResourceTypeRoleAssignment.Id,
}

// DeclaredResourceTypeIDs is every type the connector can ever emit, in either
// model. It is what the capabilities manifest declares, so the manifest stays
// complete regardless of how a deployment is configured.
func DeclaredResourceTypeIDs() []string {
	return append(append([]string{}, AllResourceTypeIDs...), SparseResourceTypeIDs...)
}

// DefaultSyncResourceTypeIDs is the set to sync when nothing else narrows the
// sync: the core RBAC types plus the sparse ones. The workload and
// configuration types are left out because they expose verb entitlements that
// never produce grants.
//
// The sparse types have to be in here even though they only produce anything
// when --use-role-assignments is set. This default is a package-level value
// built before any config is parsed, so it cannot depend on that flag; leaving
// them out filtered them away exactly when they were needed, and because
// cluster_role suppresses its own entitlements and grants under the flag, the
// sync then emitted no cluster role access at all. With the flag off their
// builders emit nothing, so naming them here costs nothing.
//
// This is a sync *filter*, not a registration list: which types the connector
// registers must not depend on it. See NewFromConfig.
func DefaultSyncResourceTypeIDs() []string {
	return []string{
		ResourceTypeNamespace.Id,
		ResourceTypeServiceAccount.Id,
		ResourceTypeRole.Id,
		ResourceTypeClusterRole.Id,
		ResourceTypeKubeUser.Id,
		ResourceTypeKubeGroup.Id,
		ResourceTypeCluster.Id,
		ResourceTypeRoleAssignment.Id,
	}
}

// AllResourceTypeIDs lists the resource types belonging to the flat model,
// including the opt-in workload/configuration types. The sparse types are not
// here because they are not part of that model; they live in
// SparseResourceTypeIDs, and DeclaredResourceTypeIDs joins the two into the set
// the connector registers and declares.
var AllResourceTypeIDs = []string{
	ResourceTypeNamespace.Id,
	ResourceTypeServiceAccount.Id,
	ResourceTypeRole.Id,
	ResourceTypeClusterRole.Id,
	ResourceTypeKubeUser.Id,
	ResourceTypeKubeGroup.Id,
	ResourceTypeConfigMap.Id,
	ResourceTypeSecret.Id,
	ResourceTypePod.Id,
	ResourceTypeNode.Id,
	ResourceTypeDeployment.Id,
	ResourceTypeStatefulSet.Id,
	ResourceTypeDaemonSet.Id,
}
