package connector

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// generateTestCert creates a self-signed x509 cert with the given CN and Organizations.
// Shared by kubeuser_test.go and kubegroup_test.go (same package, no import needed).
func generateTestCert(t *testing.T, cn string, orgs []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: orgs},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return buf.Bytes()
}

// makeKubeconfigSecret builds a corev1.Secret whose "config" key is a kubeconfig
// embedding a client certificate with the given CN and Organization fields.
func makeKubeconfigSecret(t *testing.T, name, namespace, cn string, orgs []string) *corev1.Secret {
	t.Helper()
	certPEM := generateTestCert(t, cn, orgs)
	cfg := clientcmdapi.NewConfig()
	cfg.AuthInfos[cn] = &clientcmdapi.AuthInfo{ClientCertificateData: certPEM}
	data, err := clientcmd.Write(*cfg)
	require.NoError(t, err)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       map[string][]byte{"config": data},
	}
}

// TestKubeUserBuilderPhase3BuildsCache verifies that List() Phase 3 discovers
// cert-based users AND seals the shared secrets cache on the Kubernetes struct.
func TestKubeUserBuilderPhase3BuildsCache(t *testing.T) {
	secret := makeKubeconfigSecret(t, "kc-secret", "default", "alice", []string{"dev-team"})
	fakeClient := fake.NewSimpleClientset(secret)

	k8s := &Kubernetes{client: fakeClient}
	builder := newKubeUserBuilder(fakeClient, k8s)

	phaseToken, err := marshalPhaseToken(phaseSecrets, "")
	require.NoError(t, err)

	ctx := context.Background()
	resources, nextToken, _, err := builder.List(ctx, nil, &pagination.Token{Token: phaseToken})

	require.NoError(t, err)
	assert.Empty(t, nextToken, "Phase 3 should complete in one call")
	require.Len(t, resources, 1)
	assert.Equal(t, "alice", resources[0].DisplayName)

	// The secrets cache must be sealed after Phase 3 completes.
	k8s.secretsMu.Lock()
	result := k8s.secretsResult
	k8s.secretsMu.Unlock()
	require.NotNil(t, result, "secretsResult must be sealed after Phase 3")
	assert.Equal(t, []string{"alice"}, result.Usernames)
	assert.Equal(t, []string{"alice"}, result.GroupMembers["dev-team"])
}

// makeKubeconfigSecretWithEmptyCN creates a secret where the cert has an empty CN
// but the kubeconfig auth-info key is "service-account-1".
func makeKubeconfigSecretWithEmptyCN(t *testing.T, name, namespace string, orgs []string) *corev1.Secret {
	t.Helper()
	certPEM := generateTestCert(t, "", orgs) // empty CN
	cfg := clientcmdapi.NewConfig()
	cfg.AuthInfos["service-account-1"] = &clientcmdapi.AuthInfo{ClientCertificateData: certPEM}
	data, err := clientcmd.Write(*cfg)
	require.NoError(t, err)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       map[string][]byte{"config": data},
	}
}

// TestKubeUserBuilderPhase3EmptyCNSkipped verifies that a cert with an empty CN
// is skipped entirely: no user resource and no group membership. The CN is the
// identity Kubernetes authenticates; the kubeconfig auth-info key is an arbitrary
// local label, and membership grants for it would dangle (no matching resource).
func TestKubeUserBuilderPhase3EmptyCNSkipped(t *testing.T) {
	secret := makeKubeconfigSecretWithEmptyCN(t, "kc-empty-cn", "default", []string{"ops-team"})
	fakeClient := fake.NewSimpleClientset(secret)

	k8s := &Kubernetes{client: fakeClient}
	builder := newKubeUserBuilder(fakeClient, k8s)

	phaseToken, err := marshalPhaseToken(phaseSecrets, "")
	require.NoError(t, err)

	ctx := context.Background()
	resources, nextToken, _, err := builder.List(ctx, nil, &pagination.Token{Token: phaseToken})

	require.NoError(t, err)
	assert.Empty(t, nextToken)
	assert.Empty(t, resources, "empty CN must not produce a user resource")

	k8s.secretsMu.Lock()
	result := k8s.secretsResult
	k8s.secretsMu.Unlock()
	require.NotNil(t, result)
	assert.Empty(t, result.Usernames, "empty CN must not be added to Usernames")
	assert.Empty(t, result.GroupMembers["ops-team"],
		"empty CN must not produce group membership entries")
}

// TestKubeUserBuilderPhase3MultiPageAccumulates verifies that Phase 3 correctly merges
// data across two pages. It pre-seeds the accumulator (simulating page 1) then calls
// List() for page 2 with a non-empty continue token; the sealed result must contain
// entries from both pages.
func TestKubeUserBuilderPhase3MultiPageAccumulates(t *testing.T) {
	// Page 2 has bob in ops-team.
	secret2 := makeKubeconfigSecret(t, "kc-page2", "default", "bob", []string{"ops-team"})
	fakeClient := fake.NewSimpleClientset(secret2)

	k8s := &Kubernetes{client: fakeClient}
	builder := newKubeUserBuilder(fakeClient, k8s)

	// Pre-seed accumulator as if page 1 already processed "alice" in dev-team.
	k8s.secretsMu.Lock()
	k8s.secretsAccumulator = &secretsScanResult{
		Usernames:    []string{"alice"},
		GroupMembers: map[string][]string{"dev-team": {"alice"}},
	}
	k8s.secretsMu.Unlock()

	// Non-empty continue token → accumulator init is skipped (page 2).
	phaseToken, err := marshalPhaseToken(phaseSecrets, "fake-continue-token")
	require.NoError(t, err)

	ctx := context.Background()
	resources, nextToken, _, err := builder.List(ctx, nil, &pagination.Token{Token: phaseToken})

	require.NoError(t, err)
	assert.Empty(t, nextToken, "no more pages after the final page")
	require.Len(t, resources, 1, "page 2 should emit bob as a new user resource")
	assert.Equal(t, "bob", resources[0].DisplayName)

	// Sealed result must contain both pages' data.
	k8s.secretsMu.RLock()
	result := k8s.secretsResult
	acc := k8s.secretsAccumulator
	k8s.secretsMu.RUnlock()

	require.NotNil(t, result)
	assert.Nil(t, acc, "accumulator must be nil after sealing")
	assert.ElementsMatch(t, []string{"alice", "bob"}, result.Usernames)
	assert.ElementsMatch(t, []string{"alice"}, result.GroupMembers["dev-team"])
	assert.ElementsMatch(t, []string{"bob"}, result.GroupMembers["ops-team"])
}

// TestKubeUserBuilderPhase3DeduplicatesUsers verifies that the same CN in multiple
// secrets produces one user resource and one Usernames entry.
func TestKubeUserBuilderPhase3DeduplicatesUsers(t *testing.T) {
	secret1 := makeKubeconfigSecret(t, "secret-1", "default", "alice", nil)
	secret2 := makeKubeconfigSecret(t, "secret-2", "default", "alice", nil)
	fakeClient := fake.NewSimpleClientset(secret1, secret2)

	k8s := &Kubernetes{client: fakeClient}
	builder := newKubeUserBuilder(fakeClient, k8s)

	phaseToken, err := marshalPhaseToken(phaseSecrets, "")
	require.NoError(t, err)

	ctx := context.Background()
	resources, _, _, err := builder.List(ctx, nil, &pagination.Token{Token: phaseToken})

	require.NoError(t, err)
	assert.Len(t, resources, 1, "duplicate CN must produce exactly one user resource")

	k8s.secretsMu.Lock()
	result := k8s.secretsResult
	k8s.secretsMu.Unlock()
	assert.Len(t, result.Usernames, 1)
}

// TestKubeUserBuilderPhase3SecretsListForbidden verifies that Phase 3 is
// best-effort: when the connector's credentials cannot list secrets, the
// mandatory kube_user sync must complete without error and the secrets
// result must still be sealed (empty) so kubeGroupBuilder.Grants can run.
func TestKubeUserBuilderPhase3SecretsListForbidden(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	fakeClient.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewForbidden(
			schema.GroupResource{Resource: "secrets"}, "", fmt.Errorf("no cluster-wide secret access"))
	})

	k8s := &Kubernetes{client: fakeClient}
	builder := newKubeUserBuilder(fakeClient, k8s)

	phaseToken, err := marshalPhaseToken(phaseSecrets, "")
	require.NoError(t, err)

	ctx := context.Background()
	resources, nextToken, _, err := builder.List(ctx, nil, &pagination.Token{Token: phaseToken})

	require.NoError(t, err, "a forbidden secrets list must not fail the user sync")
	assert.Empty(t, nextToken, "sync must complete cleanly")
	assert.Empty(t, resources)

	k8s.secretsMu.Lock()
	result := k8s.secretsResult
	k8s.secretsMu.Unlock()
	require.NotNil(t, result, "secrets result must be sealed even on failure")
	assert.Empty(t, result.Usernames)
	assert.Empty(t, result.GroupMembers)
}
