package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// TestSecretCredentialType verifies the Kubernetes secret type -> NHI spine
// CredentialType + axis-2 detail mapping.
func TestSecretCredentialType(t *testing.T) {
	testCases := []struct {
		name       string
		secretType corev1.SecretType
		wantType   v2.SecretTrait_CredentialType
		wantDetail string
	}{
		{
			name:       "service account token",
			secretType: corev1.SecretTypeServiceAccountToken,
			wantType:   v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET,
			wantDetail: "k8s.secret.service_account_token",
		},
		{
			name:       "tls is a certificate",
			secretType: corev1.SecretTypeTLS,
			wantType:   v2.SecretTrait_CREDENTIAL_TYPE_CERTIFICATE,
			wantDetail: "k8s.secret.tls",
		},
		{
			name:       "ssh auth is an asymmetric key",
			secretType: corev1.SecretTypeSSHAuth,
			wantType:   v2.SecretTrait_CREDENTIAL_TYPE_ASYMMETRIC_KEY,
			wantDetail: "k8s.secret.ssh_auth",
		},
		{
			name:       "opaque is a static secret",
			secretType: corev1.SecretTypeOpaque,
			wantType:   v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET,
			wantDetail: "k8s.secret.opaque",
		},
		{
			name:       "basic auth is a static secret",
			secretType: corev1.SecretTypeBasicAuth,
			wantType:   v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET,
			wantDetail: "k8s.secret.basic_auth",
		},
		{
			name:       "empty type defaults to opaque",
			secretType: corev1.SecretType(""),
			wantType:   v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET,
			wantDetail: "k8s.secret.opaque",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotDetail := secretCredentialType(tc.secretType)
			assert.Equal(t, tc.wantType, gotType)
			assert.Equal(t, tc.wantDetail, gotDetail)
		})
	}
}
