package connector

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
)

// grpcMaxMessageBytes is gRPC's default MaxRecvMsgSize. The SDK does not raise
// it, so a ListGrants response above this aborts the sync with ResourceExhausted.
const grpcMaxMessageBytes = 4 * 1024 * 1024

// fatAssignmentResource builds a (cluster role, scope) pair carrying one
// contributing binding per binding, which is what makes its profile grow.
func fatAssignmentResource(t *testing.T, bindings int) *v2.Resource {
	t.Helper()

	contributors := make([]contributingBinding, 0, bindings)
	for i := 0; i < bindings; i++ {
		contributors = append(contributors, contributingBinding{
			Name:              fmt.Sprintf("platform-view-binding-%04d", i),
			Kind:              ResourceTypeClusterRoleBinding,
			CreationTimestamp: "2026-08-12T00:00:00Z",
		})
	}

	resource, err := roleAssignmentResource(assignmentKey{
		scopeType: ResourceTypeCluster.Id,
		scopeID:   clusterResourceID,
		role:      "view",
	}, contributors)
	require.NoError(t, err)
	return resource
}

// listGrantsBytes measures the wire size of the response the connector hands
// back, which is what the 4 MiB limit applies to.
func listGrantsBytes(t *testing.T, grants []*v2.Grant) int {
	t.Helper()
	b, err := proto.Marshal(v2.GrantsServiceListGrantsResponse_builder{List: grants}.Build())
	require.NoError(t, err)
	return len(b)
}

// TestGrantEntitlementResourceKeepsIdentity is the compatibility guard: stripping
// must not move any ID, or every previously synced grant would be re-keyed.
func TestGrantEntitlementResourceKeepsIdentity(t *testing.T) {
	full := fatAssignmentResource(t, 50)
	stripped := GrantEntitlementResource(full)

	require.Equal(t, full.GetId().GetResource(), stripped.GetId().GetResource())
	require.Equal(t, full.GetId().GetResourceType(), stripped.GetId().GetResourceType())
	require.Equal(t, entitlement.NewEntitlementID(full, assignedEntitlement),
		entitlement.NewEntitlementID(stripped, assignedEntitlement))

	// The parent survives: a partial sync refetches an unstored entitlement
	// resource by ID and parent together.
	require.NotNil(t, stripped.GetParentResourceId())
	require.Equal(t, full.GetParentResourceId().GetResource(), stripped.GetParentResourceId().GetResource())
	require.Equal(t, full.GetParentResourceId().GetResourceType(), stripped.GetParentResourceId().GetResourceType())

	principal := GenerateResourceForGrant("user-0001@example.com", ResourceTypeKubeUser.Id)
	require.Equal(t,
		grant.NewGrant(full, assignedEntitlement, principal).GetId(),
		grant.NewGrant(stripped, assignedEntitlement, principal).GetId(),
	)

	// The profile is what must not travel.
	require.Nil(t, stripped.GetAnnotations())
}

func TestGrantEntitlementResourceNilID(t *testing.T) {
	res := &v2.Resource{}
	require.Same(t, res, GrantEntitlementResource(res),
		"a resource with no ID is handed back untouched for the SDK to reject")
}

// TestRoleAssignmentGrantsStayUnderMessageLimit covers CXP-919: a single
// (cluster role, scope) pair carrying many bindings and many subjects used to
// exceed the gRPC message limit because each grant embedded the whole resource.
func TestRoleAssignmentGrantsStayUnderMessageLimit(t *testing.T) {
	// Shapes measured to abort before the fix.
	for _, tc := range []struct{ bindings, subjects int }{
		{175, 175},
		{60, 600},
		{500, 500},
		{1000, 2000},
	} {
		t.Run(fmt.Sprintf("bindings=%d/subjects=%d", tc.bindings, tc.subjects), func(t *testing.T) {
			resource := fatAssignmentResource(t, tc.bindings)

			grants := make([]*v2.Grant, 0, tc.subjects)
			for i := 0; i < tc.subjects; i++ {
				gs, err := GrantRoleToSubject(context.Background(),
					userSubject(fmt.Sprintf("user-%04d@example.com", i)), resource, assignedEntitlement, ExternalMatchConfig{})
				require.NoError(t, err)
				grants = append(grants, gs...)
			}

			size := listGrantsBytes(t, grants)
			t.Logf("bindings=%d subjects=%d -> %d bytes (%.2f MiB)",
				tc.bindings, tc.subjects, size, float64(size)/(1024*1024))
			require.Less(t, size, grpcMaxMessageBytes,
				"ListGrants response must stay under gRPC's 4 MiB limit")
		})
	}
}

// TestGrantCostIsIndependentOfProfileSize is the real invariant: growing the
// resource profile must not grow the grants. Without it, any future profile
// addition silently re-introduces CXP-919.
func TestGrantCostIsIndependentOfProfileSize(t *testing.T) {
	const subjects = 100

	sizeWith := func(bindings int) int {
		resource := fatAssignmentResource(t, bindings)
		grants := make([]*v2.Grant, 0, subjects)
		for i := 0; i < subjects; i++ {
			gs, err := GrantRoleToSubject(context.Background(),
				userSubject(fmt.Sprintf("user-%04d@example.com", i)), resource, assignedEntitlement, ExternalMatchConfig{})
			require.NoError(t, err)
			grants = append(grants, gs...)
		}
		return listGrantsBytes(t, grants)
	}

	small := sizeWith(1)
	large := sizeWith(2000)

	require.Equal(t, small, large,
		"grant payload must not depend on how many contributing bindings the pair has")
}

// TestClusterRoleGrantCostIsIndependentOfRules is the flat-model half: a
// rule-heavy (typically aggregated) cluster role must not inflate its grants.
func TestClusterRoleGrantCostIsIndependentOfRules(t *testing.T) {
	const subjects = 100

	sizeWith := func(ruleCount int) int {
		rules := make([]rbacv1.PolicyRule, 0, ruleCount)
		for i := 0; i < ruleCount; i++ {
			rules = append(rules, rbacv1.PolicyRule{
				APIGroups: []string{fmt.Sprintf("group%d.example.com", i)},
				Resources: []string{"widgets", "widgets/status", "widgets/finalizers"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			})
		}
		resource, err := clusterRoleResource(&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "admin", UID: "1234-5678"},
			Rules:      rules,
		}, false)
		require.NoError(t, err)

		grants := make([]*v2.Grant, 0, subjects)
		for i := 0; i < subjects; i++ {
			gs, err := GrantRoleToSubject(context.Background(),
				userSubject(fmt.Sprintf("user-%04d@example.com", i)), resource, clusterScopedMember, ExternalMatchConfig{})
			require.NoError(t, err)
			grants = append(grants, gs...)
		}
		return listGrantsBytes(t, grants)
	}

	require.Equal(t, sizeWith(0), sizeWith(300),
		"grant payload must not depend on the cluster role's rule count")
}
