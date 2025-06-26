package connector

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"google.golang.org/protobuf/types/known/structpb"
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

// generateWildcardResource creates a special resource that represents all resources of a specific type
// for use with role permissions that apply to all instances of a resource type.
func generateWildcardResource(resourceType *v2.ResourceType) (*v2.Resource, error) {
	// Create a resource ID with the wildcard pattern
	resourceID := "*"
	displayName := "All " + resourceType.DisplayName

	// Create basic profile data
	profile := map[string]interface{}{
		"name": displayName,
		"uid":  "wildcard-" + resourceType.Id,
	}

	// Handle different resource types differently to add appropriate traits.
	switch resourceType.Id {
	case ResourceTypeSecret.Id:
		// For secrets, use NewSecretResource with SecretTrait.
		secretOptions := []rs.SecretTraitOption{
			// Set creation time to now
			rs.WithSecretCreatedAt(time.Now()),
			// Add profile to trait.
			func(t *v2.SecretTrait) error {
				profileStruct, err := structpb.NewStruct(profile)
				if err != nil {
					return err
				}
				t.Profile = profileStruct
				return nil
			},
		}

		options := []rs.ResourceOption{
			rs.WithDescription("Represents all secrets in the cluster"),
		}

		return rs.NewSecretResource(
			displayName,
			resourceType,
			resourceID,
			secretOptions,
			options...,
		)
	case ResourceTypeServiceAccount.Id:
		// For service accounts, use NewUserResource with UserTrait.
		userOptions := []rs.UserTraitOption{
			rs.WithUserProfile(profile),
			rs.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
			rs.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_SERVICE),
		}

		return rs.NewUserResource(
			displayName,
			resourceType,
			resourceID,
			userOptions,
		)
	case ResourceTypeRole.Id, ResourceTypeClusterRole.Id:
		// For roles, use NewRoleResource with RoleTrait.
		return rs.NewRoleResource(
			displayName,
			resourceType,
			resourceID,
			[]rs.RoleTraitOption{rs.WithRoleProfile(profile)},
		)
	default:
		// For other resource types, use standard NewResource.
		return rs.NewResource(
			displayName,
			resourceType,
			resourceID,
			rs.WithDescription("Represents all resources of type "+resourceType.DisplayName),
		)
	}
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
