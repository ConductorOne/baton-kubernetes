package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestStatefulSetResource(t *testing.T) {
	// Create a test StatefulSet
	testStatefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-statefulset",
			Namespace: "test-namespace",
			UID:       types.UID("test-uid"),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: int32Ptr(3),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "test-app",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "test-app",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "test-image",
						},
					},
				},
			},
		},
	}

	// Call the statefulSetResource function
	resource, err := statefulSetResource(testStatefulSet)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, resource)
	assert.Equal(t, "test-statefulset", resource.DisplayName)
	assert.Equal(t, resourceTypeStatefulSet.Id, resource.Id.ResourceType)
	assert.Equal(t, "test-namespace/test-statefulset", resource.Id.Resource)

	// Check that the resource has the correct parent ID
	parentID, err := namespaceResourceID("test-namespace")
	require.NoError(t, err)
	assert.Equal(t, parentID, resource.ParentResourceId)

	// Check external ID
	require.NotNil(t, resource.ExternalId)
	assert.Equal(t, "test-uid", resource.ExternalId.Id)
}

func TestStatefulSetBuilderList(t *testing.T) {
	// Create test StatefulSets
	sts1 := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-statefulset-1",
			Namespace: "test-namespace",
			UID:       types.UID("test-uid-1"),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: int32Ptr(3),
		},
	}

	sts2 := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-statefulset-2",
			Namespace: "test-namespace",
			UID:       types.UID("test-uid-2"),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: int32Ptr(2),
		},
	}

	// Create a fake client with the test StatefulSets
	fakeClient := fake.NewSimpleClientset(sts1, sts2)

	// Create a statefulSetBuilder instance using the fake client
	builder := &statefulSetBuilder{
		client: fakeClient,
	}

	// Call List method
	ctx := context.Background()
	pToken := &pagination.Token{}
	resources, nextPageToken, ann, err := builder.List(ctx, nil, pToken)

	// Assertions
	require.NoError(t, err)
	require.Nil(t, ann)
	// Expecting 3 resources: the wildcard resource plus the 2 test StatefulSets
	require.Len(t, resources, 3)
	assert.Empty(t, nextPageToken)

	// Find and verify the wildcard resource
	var wildcardResourceFound bool
	// Verify the real StatefulSet resources
	var foundSts1, foundSts2 bool

	for _, res := range resources {
		switch {
		case res.Id.Resource == "*":
			wildcardResourceFound = true
			assert.Equal(t, resourceTypeStatefulSet.Id, res.Id.ResourceType)
			assert.Contains(t, res.DisplayName, "All")
		case res.DisplayName == "test-statefulset-1":
			foundSts1 = true
			assert.Equal(t, "test-namespace/test-statefulset-1", res.Id.Resource)
		case res.DisplayName == "test-statefulset-2":
			foundSts2 = true
			assert.Equal(t, "test-namespace/test-statefulset-2", res.Id.Resource)
		}
	}

	assert.True(t, wildcardResourceFound, "Wildcard StatefulSet resource should be in the results")
	assert.True(t, foundSts1, "test-statefulset-1 should be in the results")
	assert.True(t, foundSts2, "test-statefulset-2 should be in the results")
}

func TestStatefulSetBuilderEntitlements(t *testing.T) {
	// Create a fake client
	fakeClient := fake.NewSimpleClientset()

	// Create a statefulSetBuilder instance using the fake client
	builder := &statefulSetBuilder{
		client: fakeClient,
	}

	// Create a test resource
	testResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeStatefulSet.Id,
			Resource:     "test-namespace/test-statefulset",
		},
		DisplayName: "test-statefulset",
	}

	// Call Entitlements method
	ctx := context.Background()
	pToken := &pagination.Token{}
	entitlements, nextPageToken, ann, err := builder.Entitlements(ctx, testResource, pToken)

	// Assertions
	require.NoError(t, err)
	require.Nil(t, ann)
	assert.Empty(t, nextPageToken)

	// Verify standard verb entitlements
	standardVerbCount := len(standardResourceVerbs)
	// Plus 1 for the "scale" verb specific to StatefulSets
	expectedEntitlementCount := standardVerbCount + 1
	require.Len(t, entitlements, expectedEntitlementCount)

	// Check for scale entitlement specifically
	foundScale := false
	for _, ent := range entitlements {
		if ent.DisplayName == "scale test-statefulset" {
			foundScale = true
			assert.Contains(t, ent.Description, "scale")
			assert.Len(t, ent.GrantableTo, 2) // Role and ClusterRole
		}
	}
	assert.True(t, foundScale, "scale entitlement should be present")
}

func TestStatefulSetBuilderGrants(t *testing.T) {
	// Create a fake client
	fakeClient := fake.NewSimpleClientset()

	// Create a statefulSetBuilder instance using the fake client
	builder := &statefulSetBuilder{
		client: fakeClient,
	}

	// Create a test resource
	testResource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeStatefulSet.Id,
			Resource:     "test-namespace/test-statefulset",
		},
		DisplayName: "test-statefulset",
	}

	// Call Grants method
	ctx := context.Background()
	pToken := &pagination.Token{}
	grants, nextPageToken, ann, err := builder.Grants(ctx, testResource, pToken)

	// Assertions - StatefulSets should return no grants
	require.NoError(t, err)
	require.Nil(t, ann)
	assert.Empty(t, nextPageToken)
	assert.Empty(t, grants)
}

// Helper function to create int32 pointer.
func int32Ptr(i int32) *int32 {
	return &i
}
