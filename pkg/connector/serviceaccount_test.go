package connector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// testServiceAccount is the shape that broke resource creation: a ServiceAccount
// carrying both a mounted secret and an image pull secret. structpb rejects a raw
// []string, so these two lists have to reach the profile as []interface{}.
func testServiceAccount(name, namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID("uid-" + name),
		},
		Secrets: []corev1.ObjectReference{
			{Name: name + "-token"},
		},
		ImagePullSecrets: []corev1.LocalObjectReference{
			{Name: "registry-cred"},
			{Name: "backup-registry-cred"},
		},
	}
}

// TestServiceAccountResourceWithSecrets is the regression test for CXP-1075: a
// ServiceAccount with non-empty secrets or imagePullSecrets used to fail resource
// creation with "proto: invalid type: []string" and be dropped from the sync.
func TestServiceAccountResourceWithSecrets(t *testing.T) {
	resource, err := serviceAccountResource(testServiceAccount("reloader-reloader", "ttd-system"))

	require.NoError(t, err)
	require.NotNil(t, resource)
	assert.Equal(t, "reloader-reloader (ttd-system)", resource.GetDisplayName())
	assert.Equal(t, ResourceTypeServiceAccount.Id, resource.GetId().GetResourceType())
	assert.Equal(t, "ttd-system/reloader-reloader", resource.GetId().GetResource())

	// Both lists must survive the round trip through structpb as real lists,
	// not a joined string.
	profile := resource.GetProfile().AsMap()
	assert.Equal(t, []interface{}{"reloader-reloader-token"}, profile["secrets"])
	assert.Equal(t, []interface{}{"registry-cred", "backup-registry-cred"}, profile["imagePullSecrets"])
}

// TestServiceAccountResourceWithoutSecrets pins the omission behaviour: absent
// lists leave the keys out of the profile rather than serializing empty lists.
func TestServiceAccountResourceWithoutSecrets(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "default",
			UID:       types.UID("uid-default"),
		},
	}

	resource, err := serviceAccountResource(sa)

	require.NoError(t, err)
	profile := resource.GetProfile().AsMap()
	assert.NotContains(t, profile, "secrets")
	assert.NotContains(t, profile, "imagePullSecrets")
}

// TestServiceAccountBuilderListEmitsAccountsWithSecrets covers the silent drop
// itself, which lives in the caller: List logs the resource-creation error and
// continues, so a broken profile removed the account from the sync while the sync
// still reported success. A unit test on serviceAccountResource alone would not
// have caught that.
func TestServiceAccountBuilderListEmitsAccountsWithSecrets(t *testing.T) {
	withSecrets := testServiceAccount("cert-manager", "ttd-system")
	plain := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "ttd-system",
			UID:       types.UID("uid-default"),
		},
	}

	builder := newServiceAccountBuilder(fake.NewSimpleClientset(withSecrets, plain), nil)

	// List short-circuits on a nil parent, so the namespace has to be real for
	// this to exercise anything.
	parentID, err := NamespaceResourceID("ttd-system")
	require.NoError(t, err)

	resources, results, err := builder.List(context.Background(), parentID, rs.SyncOpAttrs{})

	require.NoError(t, err)
	require.NotNil(t, results)
	assert.Empty(t, results.NextPageToken)

	names := make(map[string]*v2.Resource, len(resources))
	for _, res := range resources {
		names[res.GetId().GetResource()] = res
	}
	require.Contains(t, names, "ttd-system/cert-manager", "ServiceAccount with secrets must not be skipped")
	require.Contains(t, names, "ttd-system/default")
	require.Len(t, resources, 2)
}
