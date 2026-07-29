package connector

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPolicyRulesProfile(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods", "configmaps"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "update", "patch"},
		},
		{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{"app-db-password"},
			Verbs:         []string{"get"},
		},
	}

	p := PolicyRulesProfile(rules)

	assert.Equal(t, 3, p[profileKeyRuleCount])
	assert.Equal(t, toAnySlice([]string{"", "apps"}), p[profileKeyAPIGroups])
	assert.Equal(t, toAnySlice([]string{"configmaps", "deployments", "pods", "secrets"}), p[profileKeyResources])
	assert.Equal(t, toAnySlice([]string{"get", "list", "patch", "update", "watch"}), p[profileKeyVerbs])
	assert.Equal(t, toAnySlice([]string{"app-db-password"}), p[profileKeyResourceNames])

	// patch and update are write verbs, so the role is flagged as modifying.
	assert.Equal(t, true, p[profileKeyCanModify])
	assert.Equal(t, toAnySlice([]string{"patch", "update"}), p[profileKeyModifiableVerbs])
	assert.Equal(t, 2, p[profileKeyModifiableVerbCount])

	// The structured rules preserve each rule separately, including resourceNames.
	structured, ok := p[profileKeyRules].([]interface{})
	require.True(t, ok)
	require.Len(t, structured, 3)
	third, ok := structured[2].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, toAnySlice([]string{"app-db-password"}), third[profileKeyResourceNames])
	assert.Equal(t, toAnySlice([]string{"get"}), third[profileKeyVerbs])
	// Keys with no values are omitted rather than serialized as empty lists.
	assert.NotContains(t, third, profileKeyNonResourceURLs)
}

func TestPolicyRulesProfileReadOnly(t *testing.T) {
	p := PolicyRulesProfile([]rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get", "list", "watch"},
	}})

	assert.Equal(t, false, p[profileKeyCanModify])
	assert.Equal(t, 0, p[profileKeyModifiableVerbCount])
	assert.Empty(t, p[profileKeyModifiableVerbs])
	assert.NotContains(t, p, profileKeyResourceNames)
}

func TestPolicyRulesProfileEscalationAndWildcard(t *testing.T) {
	p := PolicyRulesProfile([]rbacv1.PolicyRule{
		{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
		{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"bind", "escalate"}},
		{NonResourceURLs: []string{"/healthz", "/metrics"}, Verbs: []string{"get"}},
	})

	assert.Equal(t, true, p[profileKeyCanModify])
	assert.Equal(t, toAnySlice([]string{"*", "bind", "escalate"}), p[profileKeyModifiableVerbs])
	assert.Equal(t, toAnySlice([]string{"/healthz", "/metrics"}), p[profileKeyNonResourceURLs])
}

func TestPolicyRulesProfileNoRules(t *testing.T) {
	p := PolicyRulesProfile(nil)

	assert.Equal(t, 0, p[profileKeyRuleCount])
	assert.Equal(t, false, p[profileKeyCanModify])
	assert.Empty(t, p[profileKeyRules])
}

// TestRoleResourceIncludesRules verifies the rules reach the emitted resource's
// profile, not just the helper's return value.
func TestRoleResourceIncludesRules(t *testing.T) {
	role := &rbacv1.Role{}
	role.Name = "app-operator"
	role.Namespace = "team-a"
	role.Rules = []rbacv1.PolicyRule{{
		APIGroups: []string{"apps"},
		Resources: []string{"deployments"},
		Verbs:     []string{"get", "delete"},
	}}

	resource, err := roleResource(role)
	require.NoError(t, err)
	assert.Equal(t, "team-a/app-operator", resource.GetId().GetResource())

	profile := resource.GetProfile().AsMap()
	assert.Equal(t, float64(1), profile[profileKeyRuleCount])
	assert.Equal(t, true, profile[profileKeyCanModify])
	assert.Equal(t, []interface{}{"delete"}, profile[profileKeyModifiableVerbs])
	assert.Equal(t, []interface{}{"deployments"}, profile[profileKeyResources])
	require.Len(t, profile[profileKeyRules], 1)
}

// TestClusterRoleResourceAggregatedRules verifies an aggregated ClusterRole is
// flagged and its controller-materialized rules are captured.
func TestClusterRoleResourceAggregatedRules(t *testing.T) {
	cr := &rbacv1.ClusterRole{}
	cr.Name = "c1-monitoring"
	cr.AggregationRule = &rbacv1.AggregationRule{
		ClusterRoleSelectors: []metav1.LabelSelector{
			{MatchLabels: map[string]string{"example.com/aggregate-to-monitoring": "true"}},
		},
	}
	// The aggregation controller writes the effective rules into the object.
	cr.Rules = []rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"events"},
		Verbs:     []string{"get", "list", "watch"},
	}}

	resource, err := clusterRoleResource(cr)
	require.NoError(t, err)

	profile := resource.GetProfile().AsMap()
	assert.Equal(t, true, profile[profileKeyAggregated])
	assert.Equal(t, false, profile[profileKeyCanModify], "read-only aggregated rules must not be flagged")
	assert.Equal(t, []interface{}{"events"}, profile[profileKeyResources])
	assert.Contains(t, profile, "aggregationRule", "selector kept for provenance")
}

func TestFormatTimestamp(t *testing.T) {
	// A fixed instant in a non-UTC zone must render as UTC RFC 3339, matching
	// what the Kubernetes API returns.
	loc := time.FixedZone("UTC-3", -3*60*60)
	ts := metav1.NewTime(time.Date(2026, 7, 29, 15, 56, 5, 0, loc))
	assert.Equal(t, "2026-07-29T18:56:05Z", FormatTimestamp(ts))

	// A zero timestamp yields an empty string rather than year 1.
	assert.Equal(t, "", FormatTimestamp(metav1.Time{}))
}

func TestAnnotationsToAnyMap(t *testing.T) {
	out := AnnotationsToAnyMap(map[string]string{
		"kubectl.kubernetes.io/last-applied-configuration": `{"kind":"Role","rules":[]}`,
		"meta.helm.sh/release-name":                        "monitoring",
		"example.com/owner":                                "platform",
	})

	assert.NotContains(t, out, "kubectl.kubernetes.io/last-applied-configuration",
		"the last-applied blob duplicates synced fields and must be dropped")
	assert.Equal(t, "monitoring", out["meta.helm.sh/release-name"], "other annotations are preserved")
	assert.Equal(t, "platform", out["example.com/owner"])
	assert.Len(t, out, 2)

	assert.Nil(t, AnnotationsToAnyMap(nil))
}
