package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

// sealedKubernetes returns a Kubernetes struct with secretsResult pre-populated,
// simulating the state after kubeUserBuilder.List() Phase 3 has completed.
func sealedKubernetes(groupMembers map[string][]string) *Kubernetes {
	return &Kubernetes{
		client:        fake.NewSimpleClientset(),
		secretsResult: &secretsScanResult{GroupMembers: groupMembers},
	}
}

// TestKubeGroupBuilderGrantsReadsCache verifies that Grants() returns correct
// group membership from the sealed secrets cache without scanning any secrets.
func TestKubeGroupBuilderGrantsReadsCache(t *testing.T) {
	k8s := sealedKubernetes(map[string][]string{
		"dev-team": {"alice"},
	})
	builder := newKubeGroupBuilder(fake.NewSimpleClientset(), k8s)

	groupResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: ResourceTypeKubeGroup.Id,
			Resource:     "dev-team",
		},
	}

	ctx := context.Background()
	grants, nextToken, _, err := builder.Grants(ctx, groupResource, &pagination.Token{})

	require.NoError(t, err)
	assert.Empty(t, nextToken, "Grants must complete in one call")
	require.Len(t, grants, 1)
	assert.Equal(t, "alice", grants[0].Principal.Id.Resource)
}

// TestKubeGroupBuilderGrantsEmptyGroup verifies that a group with no members
// returns an empty (non-nil) grant slice.
func TestKubeGroupBuilderGrantsEmptyGroup(t *testing.T) {
	k8s := sealedKubernetes(map[string][]string{})
	builder := newKubeGroupBuilder(fake.NewSimpleClientset(), k8s)

	groupResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: ResourceTypeKubeGroup.Id,
			Resource:     "empty-group",
		},
	}

	ctx := context.Background()
	grants, nextToken, _, err := builder.Grants(ctx, groupResource, &pagination.Token{})

	require.NoError(t, err)
	assert.Empty(t, nextToken)
	assert.Empty(t, grants)
}

// TestKubeGroupBuilderGrantsMultipleGroups verifies that a user in multiple groups
// appears as a grant principal for each group independently.
func TestKubeGroupBuilderGrantsMultipleGroups(t *testing.T) {
	k8s := sealedKubernetes(map[string][]string{
		"group-a": {"bob"},
		"group-b": {"bob"},
	})
	builder := newKubeGroupBuilder(fake.NewSimpleClientset(), k8s)

	ctx := context.Background()
	for _, groupName := range []string{"group-a", "group-b"} {
		groupResource := &v2.Resource{
			Id: &v2.ResourceId{
				ResourceType: ResourceTypeKubeGroup.Id,
				Resource:     groupName,
			},
		}
		grants, _, _, err := builder.Grants(ctx, groupResource, &pagination.Token{})
		require.NoError(t, err)
		require.Len(t, grants, 1, "group %s should have bob as member", groupName)
		assert.Equal(t, "bob", grants[0].Principal.Id.Resource)
	}
}

// TestKubeGroupBuilderGrantsMultipleMembers verifies that a group with multiple members
// returns one grant per member.
func TestKubeGroupBuilderGrantsMultipleMembers(t *testing.T) {
	k8s := sealedKubernetes(map[string][]string{
		"platform": {"alice", "bob"},
	})
	builder := newKubeGroupBuilder(fake.NewSimpleClientset(), k8s)

	groupResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: ResourceTypeKubeGroup.Id,
			Resource:     "platform",
		},
	}

	ctx := context.Background()
	grants, nextToken, _, err := builder.Grants(ctx, groupResource, &pagination.Token{})

	require.NoError(t, err)
	assert.Empty(t, nextToken)
	require.Len(t, grants, 2, "platform group should have 2 members")

	principals := map[string]bool{}
	for _, g := range grants {
		assert.Equal(t, ResourceTypeKubeUser.Id, g.Principal.Id.ResourceType)
		principals[g.Principal.Id.Resource] = true
	}
	assert.True(t, principals["alice"])
	assert.True(t, principals["bob"])
}

// TestKubeGroupBuilderGrantsNoCacheSealed verifies that Grants() degrades to
// emitting no grants when the secrets scan never ran — e.g. kube_group is synced
// without kube_user via a custom sync selection. Membership is best-effort data
// and must not fail the sync.
func TestKubeGroupBuilderGrantsNoCacheSealed(t *testing.T) {
	k8s := &Kubernetes{client: fake.NewSimpleClientset()} // secretsResult is nil
	builder := newKubeGroupBuilder(fake.NewSimpleClientset(), k8s)

	groupResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: ResourceTypeKubeGroup.Id,
			Resource:     "some-group",
		},
	}

	ctx := context.Background()
	grants, _, _, err := builder.Grants(ctx, groupResource, &pagination.Token{})

	require.NoError(t, err, "Grants() must not fail when the secrets scan never ran")
	assert.Empty(t, grants, "no membership data means no grants")
}
