package connector

import (
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"google.golang.org/protobuf/types/known/structpb"
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

	// Handle different resource types differently to add appropriate traits
	switch resourceType.Id {
	case resourceTypeSecret.Id:
		// For secrets, use NewSecretResource with SecretTrait
		secretOptions := []rs.SecretTraitOption{
			// Set creation time to now
			rs.WithSecretCreatedAt(time.Now()),
			// Add profile to trait
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
	case resourceTypeServiceAccount.Id:
		// For service accounts, use NewUserResource with UserTrait
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
	case resourceTypeRole.Id, resourceTypeClusterRole.Id:
		// For roles, use NewRoleResource with RoleTrait
		return rs.NewRoleResource(
			displayName,
			resourceType,
			resourceID,
			[]rs.RoleTraitOption{rs.WithRoleProfile(profile)},
		)
	default:
		// For other resource types, use standard NewResource
		return rs.NewResource(
			displayName,
			resourceType,
			resourceID,
			rs.WithDescription("Represents all resources of type "+resourceType.DisplayName),
		)
	}
}
