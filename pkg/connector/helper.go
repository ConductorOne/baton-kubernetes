package connector

import (
	"encoding/json"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	SubjectKindGroup          = "Group"
	SubjectKindUser           = "User"
	SubjectKindServiceAccount = "ServiceAccount"
	RBACAPIGroup              = "rbac.authorization.k8s.io"
	RBACAPIGroupV1            = "rbac.authorization.k8s.io/v1"
	RoleBindings              = "rolebindings"
)

// StringMapToAnyMap converts a map[string]string (like Kubernetes labels and annotations)
// to map[string]any so it can be properly serialized to structpb.
// This is needed because protobuf cannot directly serialize map[string]string values.
func StringMapToAnyMap(input map[string]string) map[string]any {
	if input == nil {
		return nil
	}

	result := make(map[string]any, len(input))
	for k, v := range input {
		result[k] = v
	}
	return result
}

// ParseAggregationRule marshals an AggregationRule to a map[string]interface{} for serialization.
func ParseAggregationRule(aggregationRule interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(aggregationRule)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func GenerateResourceForGrant(rName string, rType string) *v2.Resource {
	return &v2.Resource{
		Id: &v2.ResourceId{
			Resource:     rName,
			ResourceType: rType,
		},
	}
}

func GrantRoleToSubject(subject rbacv1.Subject, resource *v2.Resource, entName string) (*v2.Grant, error) {
	var grantOpts []grant.GrantOption
	if subject.Kind == SubjectKindServiceAccount {
		saName := fmt.Sprintf("%s/%s", subject.Namespace, subject.Name) // SA are always namespaced, even if they can have cluster roles bind to cluster level.
		saResource := GenerateResourceForGrant(saName, ResourceTypeServiceAccount.Id)
		g := grant.NewGrant(
			resource,
			entName,
			saResource,
		)
		return g, nil
	} else if (subject.APIGroup == RBACAPIGroup || subject.APIGroup == RBACAPIGroupV1) &&
		!strings.Contains(subject.Name, "system:") { // Ignore System subjects
		if subject.Kind == SubjectKindGroup {
			// Group grants intentionally carry no GrantExpandable annotation: vanilla
			// Kubernetes has no membership source to expand through (membership lives
			// in the authenticator — x509 O= fields, OIDC claims, cloud IAM mappers).
			// Cloud connectors (EKS/AKS/GKE) add their own expansion annotations paired
			// with ExternalResourceMatch in their custom builders.
			groupResource := GenerateResourceForGrant(subject.Name, ResourceTypeKubeGroup.Id)
			g := grant.NewGrant(
				resource,
				entName,
				groupResource,
			)
			return g, nil
		}
		if subject.Kind == SubjectKindUser {
			g := grant.NewGrant(
				resource,
				entName,
				GenerateResourceForGrant(subject.Name, ResourceTypeKubeUser.Id),
				grantOpts...,
			)
			return g, nil
		}
	}
	return nil, fmt.Errorf("unsupported subject type")
}
