package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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

// GrantRoleToSubject renders one RBAC binding subject as grants on entName.
//
// A ServiceAccount yields one grant. A User or Group yields two: the durable
// grant on kube_user / kube_group, plus an external-match carrier (see
// external_match.go). Returns an error for subject kinds we do not model, which
// callers log and skip.
//
// The error is reserved for that one meaning. A carrier that cannot be built is
// logged and dropped on its own, because the durable grant is the cluster's
// record of the binding and a failed optimization must not erase it.
func GrantRoleToSubject(
	ctx context.Context,
	subject rbacv1.Subject,
	resource *v2.Resource,
	entName string,
	matchCfg ExternalMatchConfig,
) ([]*v2.Grant, error) {
	if subject.Kind == SubjectKindServiceAccount {
		saName := fmt.Sprintf("%s/%s", subject.Namespace, subject.Name) // SA are always namespaced, even if they can have cluster roles bind to cluster level.
		saResource := GenerateResourceForGrant(saName, ResourceTypeServiceAccount.Id)
		g := grant.NewGrant(
			resource,
			entName,
			saResource,
		)
		return []*v2.Grant{g}, nil
	} else if (subject.APIGroup == RBACAPIGroup || subject.APIGroup == RBACAPIGroupV1) &&
		!strings.Contains(subject.Name, "system:") { // Ignore System subjects
		if subject.Kind == SubjectKindGroup {
			groupResource := GenerateResourceForGrant(subject.Name, ResourceTypeKubeGroup.Id)
			grants := []*v2.Grant{
				grant.NewGrant(
					resource,
					entName,
					groupResource,
				),
			}
			carrier, err := matchCfg.groupCarrierGrant(resource, entName, subject.Name)
			if err != nil {
				// Skip the carrier, keep the durable grant. Returning the error
				// here would lose both: every caller reads an error as an
				// unsupported subject kind and drops the subject entirely.
				ctxzap.Extract(ctx).Warn(
					"baton-kubernetes: failed to build external-match carrier, keeping durable group grant",
					zap.String("subject_name", subject.Name),
					zap.String("entitlement", entName),
					zap.Error(err),
				)
				return grants, nil
			}
			if carrier != nil {
				grants = append(grants, carrier)
			}
			return grants, nil
		}
		if subject.Kind == SubjectKindUser {
			grants := []*v2.Grant{
				grant.NewGrant(
					resource,
					entName,
					GenerateResourceForGrant(subject.Name, ResourceTypeKubeUser.Id),
				),
			}
			if carrier := matchCfg.userCarrierGrant(resource, entName, subject.Name); carrier != nil {
				grants = append(grants, carrier)
			}
			return grants, nil
		}
	}
	return nil, fmt.Errorf("unsupported subject type")
}
