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
	ResourceTypeBinding        = &v2.ResourceType{Id: "binding", DisplayName: "Binding", Description: "Internal type for processing RBAC bindings"}
	ResourceTypeUser           = &v2.ResourceType{Id: "user", DisplayName: SubjectTypeUser, Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	ResourceTypeGroup          = &v2.ResourceType{Id: "group", DisplayName: SubjectTypeGroup, Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}}
)

// AllResourceTypeIDs lists every resource type this connector can sync,
// including the opt-in workload/configuration types.
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
