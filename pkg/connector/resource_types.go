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

// objectPermissionAnnotations marks an object type whose permission
// entitlements are declared once for the whole type through StaticEntitlements.
// SkipEntitlements stops the syncer asking each object what it carries; the
// syncer fans the type's declaration out over them instead. Grants are
// unaffected and stay per object.
func objectPermissionAnnotations() annotations.Annotations {
	return annotations.New(&v2.OptInRequired{}, &v2.SkipEntitlements{})
}

// roleAssignmentAnnotations marks the sparse cluster role assignment type.
// SkipEntitlements is what makes it sparse: the type declares one shared
// entitlement through StaticEntitlements rather than one per resource.
func roleAssignmentAnnotations() annotations.Annotations {
	return annotations.New(&v2.OptInRequired{}, &v2.SkipEntitlements{})
}

// Resource type definitions.
var (
	ResourceTypeNamespace      = &v2.ResourceType{Id: profileKeyNamespace, DisplayName: "Namespace", Annotations: annotations.New(&v2.SkipEntitlements{})}
	ResourceTypeServiceAccount = &v2.ResourceType{
		Id:          "service_account",
		DisplayName: "Service Account",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: annotations.New(&v2.SkipEntitlements{}),
	}
	ResourceTypeRole        = &v2.ResourceType{Id: "role", DisplayName: RBACKindRole, Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE}}
	ResourceTypeClusterRole = &v2.ResourceType{Id: "cluster_role", DisplayName: "Cluster Role", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE}}
	ResourceTypeSecret      = &v2.ResourceType{Id: "secret", DisplayName: "Secret", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET}, Annotations: objectPermissionAnnotations()}
	ResourceTypeConfigMap   = &v2.ResourceType{Id: "configmap", DisplayName: "Config Map", Annotations: objectPermissionAnnotations()}
	ResourceTypeNode        = &v2.ResourceType{Id: "node", DisplayName: "Node", Annotations: objectPermissionAnnotations()}
	// Pods carry SkipSyncAnomalyDetection because their count legitimately
	// collapses: a rollout replaces every pod in a Deployment, and a drop between
	// syncs is routine churn rather than the access regression the anomaly check
	// is looking for. No other type here behaves that way — a namespace or secret
	// disappearing is worth flagging.
	ResourceTypePod = &v2.ResourceType{
		Id:          "pod",
		DisplayName: "Pod",
		Annotations: annotations.New(&v2.OptInRequired{}, &v2.SkipEntitlements{}, &v2.SkipSyncAnomalyDetection{}),
	}
	ResourceTypeDeployment  = &v2.ResourceType{Id: "deployment", DisplayName: "Deployment", Annotations: objectPermissionAnnotations()}
	ResourceTypeStatefulSet = &v2.ResourceType{Id: "statefulset", DisplayName: "Stateful Set", Annotations: objectPermissionAnnotations()}
	ResourceTypeDaemonSet   = &v2.ResourceType{Id: "daemonset", DisplayName: "Daemon Set", Annotations: objectPermissionAnnotations()}
	ResourceTypeKubeUser    = &v2.ResourceType{Id: "kube_user", DisplayName: "Kubernetes User", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	ResourceTypeKubeGroup   = &v2.ResourceType{Id: "kube_group", DisplayName: "Kubernetes Group", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}}
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
	// ResourceTypeAPIResource is one authorization target: an API resource at a
	// scope, e.g. pods in team-a, or secrets cluster-wide. Its entitlements are
	// the verbs some RBAC rule names for it, and its grants are the roles
	// conferring them.
	//
	// It replaces the per-type wildcard resources, which conflated a class of
	// objects with a scope and could never be granted. The tuple modelled here
	// is the one the API server's authorizer evaluates — (apiGroup, resource,
	// namespace) — which is also why it can carry pods/exec, an API resource
	// with no objects at all.
	//
	// It carries no trait, deliberately, for the same reason as the cluster
	// singleton: a role trait here would count a permission as classic access
	// in C1's access-model derivation.
	ResourceTypeAPIResource = &v2.ResourceType{
		Id:          "api_resource",
		DisplayName: "API Resource",
		Annotations: optInAnnotations(),
	}
	ResourceTypeBinding = &v2.ResourceType{Id: "binding", DisplayName: "Binding", Description: "Internal type for processing RBAC bindings"}
	// ResourceTypeUser and ResourceTypeGroup are the placeholder principal types
	// that external-match carrier grants point at. No syncer lists them and they
	// are absent from DeclaredResourceTypeIDs on purpose: a carrier's principal
	// is a claim about a resource in *another* app, resolved during the SDK's
	// external-resource pass, and the carrier is deleted once that pass runs.
	// Registering them would instead invite the platform to sync empty types and
	// would let a carrier collide with the durable kube_user / kube_group grant
	// it is meant to accompany. See external_match.go.
	ResourceTypeUser  = &v2.ResourceType{Id: "user", DisplayName: SubjectTypeUser, Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	ResourceTypeGroup = &v2.ResourceType{Id: "group", DisplayName: SubjectTypeGroup, Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}}
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

// GranularResourceTypeIDs lists the types belonging to the granular permission
// model.
//
// Registered unconditionally like the sparse ones, for the same reason: the
// platform's selection arrives with the sync task, so a type the connector did
// not register fails the whole sync the moment a tenant opts into it.
var GranularResourceTypeIDs = []string{
	ResourceTypeAPIResource.Id,
}

// DeclaredResourceTypeIDs is every type the connector can ever emit, in either
// model. It is what the capabilities manifest declares, so the manifest stays
// complete regardless of how a deployment is configured.
func DeclaredResourceTypeIDs() []string {
	ids := append([]string{}, AllResourceTypeIDs...)
	ids = append(ids, SparseResourceTypeIDs...)
	return append(ids, GranularResourceTypeIDs...)
}

// DefaultSyncResourceTypeIDs is the set to sync when nothing else narrows the
// sync: the core RBAC types plus the sparse ones. The workload and
// configuration types are left out because they expose verb entitlements that
// never produce grants.
//
// The sparse types have to be in here even though they only produce anything
// when --use-role-assignments is set. This default is a package-level value built
// before any config is parsed, so it cannot depend on that flag; leaving them out
// filtered them away exactly when they were needed, and because cluster_role
// suppresses its own entitlements and grants under the flag, the sync then
// emitted no cluster role access at all.
//
// api_resource has to be here, not merely registered. It is the only resource
// that can carry a permission over a class of objects, and most of RBAC is
// exactly that: the collection verbs — list, watch, create, deletecollection —
// address a collection rather than any member, so they exist nowhere else.
// Without it a sync cannot answer "who can create pods in team-a", which is the
// question the permission model was built for, and a binding in a namespace with
// no objects yet is invisible because there is nothing for its grants to land on.
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
		ResourceTypeAPIResource.Id,
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
