package connector

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/bid"
)

// testRoleResource is the entitlement-side resource the grants under test point at.
var testRoleResource = &v2.Resource{
	Id:          &v2.ResourceId{ResourceType: ResourceTypeRole.Id, Resource: "team-a/pod-reader"},
	DisplayName: "pod-reader",
}

// isCarrier reports whether a grant is an external-match carrier.
func isCarrier(g *v2.Grant) bool {
	annos := annotations.Annotations(g.GetAnnotations())
	return annos.ContainsAny(
		&v2.ExternalResourceMatchAll{},
		&v2.ExternalResourceMatch{},
		&v2.ExternalResourceMatchID{},
	)
}

// durableGrants returns the non-carrier grants, so tests about binding scope,
// dedup or cache lifetime measure access rather than carriers.
func durableGrants(grants []*v2.Grant) []*v2.Grant {
	out := make([]*v2.Grant, 0, len(grants))
	for _, g := range grants {
		if !isCarrier(g) {
			out = append(out, g)
		}
	}
	return out
}

// carrierGrants is durableGrants' complement.
func carrierGrants(grants []*v2.Grant) []*v2.Grant {
	out := make([]*v2.Grant, 0, len(grants))
	for _, g := range grants {
		if isCarrier(g) {
			out = append(out, g)
		}
	}
	return out
}

// pickMatchID returns the grant's ExternalResourceMatchID, or fails.
func pickMatchID(t *testing.T, g *v2.Grant) *v2.ExternalResourceMatchID {
	t.Helper()
	annos := annotations.Annotations(g.GetAnnotations())
	got := &v2.ExternalResourceMatchID{}
	ok, err := annos.Pick(got)
	require.NoError(t, err)
	require.True(t, ok, "grant carries no ExternalResourceMatchID")
	return got
}

// pickMatch returns the grant's key/value ExternalResourceMatch, or fails.
func pickMatch(t *testing.T, g *v2.Grant) *v2.ExternalResourceMatch {
	t.Helper()
	annos := annotations.Annotations(g.GetAnnotations())
	got := &v2.ExternalResourceMatch{}
	ok, err := annos.Pick(got)
	require.NoError(t, err)
	require.True(t, ok, "grant carries no ExternalResourceMatch")
	return got
}

// pickExpandable returns the GrantExpandable on a grant, or nil.
func pickExpandable(t *testing.T, g *v2.Grant) *v2.GrantExpandable {
	t.Helper()
	annos := annotations.Annotations(g.GetAnnotations())
	got := &v2.GrantExpandable{}
	ok, err := annos.Pick(got)
	require.NoError(t, err)
	if !ok {
		return nil
	}
	return got
}

// TestUserSubjectEmitsDurableAndCarrier verifies a User subject yields both
// grants, and that the durable one carries no annotation — otherwise the SDK
// would delete it along with the carrier.
func TestUserSubjectEmitsDurableAndCarrier(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindUser, Name: "alice@example.com", APIGroup: RBACAPIGroup}

	grants, err := GrantRoleToSubject(context.Background(), subject, testRoleResource, "member", ExternalMatchConfig{})
	require.NoError(t, err)
	require.Len(t, grants, 2)

	durable := durableGrants(grants)
	require.Len(t, durable, 1)
	assert.Equal(t, ResourceTypeKubeUser.Id, durable[0].GetPrincipal().GetId().GetResourceType())
	assert.Equal(t, "alice@example.com", durable[0].GetPrincipal().GetId().GetResource())
	assert.Empty(t, durable[0].GetAnnotations(), "the durable grant must not be deletable as a carrier")

	carriers := carrierGrants(grants)
	require.Len(t, carriers, 1)
	carrier := carriers[0]
	assert.Equal(t, ResourceTypeUser.Id, carrier.GetPrincipal().GetId().GetResourceType())
	assert.Equal(t, "alice@example.com", carrier.GetPrincipal().GetId().GetResource())

	assert.Equal(t, "alice@example.com", pickMatchID(t, carrier).GetId())

	match := pickMatch(t, carrier)
	assert.Equal(t, DefaultExternalUserMatchKey, match.GetKey())
	assert.Equal(t, "alice@example.com", match.GetValue())
	assert.Equal(t, v2.ResourceType_TRAIT_USER, match.GetResourceType())

	assert.Nil(t, pickExpandable(t, carrier),
		"a user resolves to one account; there is nothing to expand through")
}

// TestGroupSubjectEmitsDurableAndCarrier verifies the same for a Group, plus the
// expansion annotation.
func TestGroupSubjectEmitsDurableAndCarrier(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindGroup, Name: "SCRUM-HPC-ADMIN", APIGroup: RBACAPIGroup}

	grants, err := GrantRoleToSubject(context.Background(), subject, testRoleResource, "member", ExternalMatchConfig{})
	require.NoError(t, err)
	require.Len(t, grants, 2)

	durable := durableGrants(grants)
	require.Len(t, durable, 1)
	assert.Equal(t, ResourceTypeKubeGroup.Id, durable[0].GetPrincipal().GetId().GetResourceType())
	assert.Equal(t, "SCRUM-HPC-ADMIN", durable[0].GetPrincipal().GetId().GetResource())
	assert.Empty(t, durable[0].GetAnnotations(),
		"group access must stay attestable when the group matches nothing")

	carriers := carrierGrants(grants)
	require.Len(t, carriers, 1)
	carrier := carriers[0]
	assert.Equal(t, ResourceTypeGroup.Id, carrier.GetPrincipal().GetId().GetResourceType())

	assert.Equal(t, "SCRUM-HPC-ADMIN", pickMatchID(t, carrier).GetId())

	match := pickMatch(t, carrier)
	assert.Equal(t, DefaultExternalGroupMatchKey, match.GetKey())
	assert.Equal(t, "SCRUM-HPC-ADMIN", match.GetValue())
	assert.Equal(t, v2.ResourceType_TRAIT_GROUP, match.GetResourceType())

	expandable := pickExpandable(t, carrier)
	require.NotNil(t, expandable)
	assert.True(t, expandable.GetShallow(),
		"the directory's own connector resolves nesting; one level is enough")
	require.NotEmpty(t, expandable.GetEntitlementIds())
}

// TestGroupCarrierExpandableTargetsItsOwnPrincipal pins what the SDK's remap
// needs: it finds the expansion by the grant principal's bid. An expandable
// naming any other resource is silently ignored and never expands.
func TestGroupCarrierExpandableTargetsItsOwnPrincipal(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindGroup, Name: "prod-developer", APIGroup: RBACAPIGroup}

	grants, err := GrantRoleToSubject(context.Background(), subject, testRoleResource, "member", ExternalMatchConfig{})
	require.NoError(t, err)
	carriers := carrierGrants(grants)
	require.Len(t, carriers, 1)
	carrier := carriers[0]

	expandable := pickExpandable(t, carrier)
	require.NotNil(t, expandable)
	require.NotEmpty(t, expandable.GetEntitlementIds())

	wantBID, err := bid.MakeBid(carrier.GetPrincipal())
	require.NoError(t, err)

	for _, entID := range expandable.GetEntitlementIds() {
		parsed, err := bid.ParseEntitlementBid(entID)
		require.NoError(t, err)
		gotBID, err := bid.MakeBid(parsed.GetResource())
		require.NoError(t, err)
		assert.Equal(t, wantBID, gotBID,
			"every expandable entitlement must name the carrier principal, or the SDK cannot remap it")
	}
}

// TestCarrierAndDurableGrantIDsDiffer: grant identity is (principal,
// entitlement), so sharing a principal would collapse the two into one.
func TestCarrierAndDurableGrantIDsDiffer(t *testing.T) {
	for _, subject := range []rbacv1.Subject{
		{Kind: SubjectKindUser, Name: "alice", APIGroup: RBACAPIGroup},
		{Kind: SubjectKindGroup, Name: "admins", APIGroup: RBACAPIGroup},
	} {
		t.Run(subject.Kind, func(t *testing.T) {
			grants, err := GrantRoleToSubject(context.Background(), subject, testRoleResource, "member", ExternalMatchConfig{})
			require.NoError(t, err)
			require.Len(t, grants, 2)
			assert.NotEqual(t, grants[0].GetId(), grants[1].GetId())
		})
	}
}

// TestServiceAccountEmitsNoCarrier: a ServiceAccount has no directory
// counterpart, so a carrier could only match the wrong thing.
func TestServiceAccountEmitsNoCarrier(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindServiceAccount, Name: "argo", Namespace: "argocd"}

	grants, err := GrantRoleToSubject(context.Background(), subject, testRoleResource, "member", ExternalMatchConfig{})
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, ResourceTypeServiceAccount.Id, grants[0].GetPrincipal().GetId().GetResourceType())
	assert.Equal(t, "argocd/argo", grants[0].GetPrincipal().GetId().GetResource())
	assert.Empty(t, carrierGrants(grants))
}

// TestSystemSubjectsStillSkipped verifies carriers did not widen which subjects
// the connector emits.
func TestSystemSubjectsStillSkipped(t *testing.T) {
	for _, subject := range []rbacv1.Subject{
		{Kind: SubjectKindGroup, Name: "system:masters", APIGroup: RBACAPIGroup},
		{Kind: SubjectKindUser, Name: "system:kube-controller-manager", APIGroup: RBACAPIGroup},
	} {
		t.Run(subject.Name, func(t *testing.T) {
			grants, err := GrantRoleToSubject(context.Background(), subject, testRoleResource, "member", ExternalMatchConfig{})
			require.Error(t, err)
			assert.Empty(t, grants)
		})
	}
}

// TestNonRBACAPIGroupSubjectsSkipped: an unexpected apiGroup must be rejected,
// not turned into a carrier claiming a directory match.
func TestNonRBACAPIGroupSubjectsSkipped(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindUser, Name: "alice", APIGroup: "example.com"}

	grants, err := GrantRoleToSubject(context.Background(), subject, testRoleResource, "member", ExternalMatchConfig{})
	require.Error(t, err)
	assert.Empty(t, grants)
}

// TestExternalMatchConfigOverrides verifies configured keys reach the annotations.
func TestExternalMatchConfigOverrides(t *testing.T) {
	cfg := ExternalMatchConfig{
		UserMatchKey:  "userPrincipalName",
		GroupMatchKey: "displayName",
	}

	userGrants, err := GrantRoleToSubject(
		context.Background(),
		rbacv1.Subject{Kind: SubjectKindUser, Name: "alice@corp.example", APIGroup: RBACAPIGroup},
		testRoleResource, "member", cfg)
	require.NoError(t, err)
	userCarrier := carrierGrants(userGrants)
	require.Len(t, userCarrier, 1)
	assert.Equal(t, "userPrincipalName", pickMatch(t, userCarrier[0]).GetKey())

	groupGrants, err := GrantRoleToSubject(
		context.Background(),
		rbacv1.Subject{Kind: SubjectKindGroup, Name: "eng", APIGroup: RBACAPIGroup},
		testRoleResource, "member", cfg)
	require.NoError(t, err)
	groupCarrier := carrierGrants(groupGrants)
	require.Len(t, groupCarrier, 1)
	assert.Equal(t, "displayName", pickMatch(t, groupCarrier[0]).GetKey())
}

// TestGroupCarrierMemberEntitlementSlug pins the slug the identity source
// actually emits. The SDK looks up NewEntitlementID(matchedPrincipal, slug) as an
// exact string, and a source's entitlement ID and Slug field can disagree —
// taking the Slug at face value resolves to nothing and drops the expansion.
func TestGroupCarrierMemberEntitlementSlug(t *testing.T) {
	grants, err := GrantRoleToSubject(
		context.Background(),
		rbacv1.Subject{Kind: SubjectKindGroup, Name: "eng", APIGroup: RBACAPIGroup},
		testRoleResource, "member", ExternalMatchConfig{})
	require.NoError(t, err)

	carriers := carrierGrants(grants)
	require.Len(t, carriers, 1)
	expandable := pickExpandable(t, carriers[0])
	require.NotNil(t, expandable)

	var slugs []string
	for _, entID := range expandable.GetEntitlementIds() {
		parsed, err := bid.ParseEntitlementBid(entID)
		require.NoError(t, err)
		slugs = append(slugs, parsed.GetSlug())
	}
	assert.Equal(t, []string{"members"}, slugs)
}

// TestExternalMatchConfigDefaults verifies the zero value is usable, since
// library callers may not set it.
func TestExternalMatchConfigDefaults(t *testing.T) {
	got := ExternalMatchConfig{}.withDefaults()
	assert.Equal(t, DefaultExternalUserMatchKey, got.UserMatchKey)
	assert.Equal(t, DefaultExternalGroupMatchKey, got.GroupMatchKey)

	partial := ExternalMatchConfig{GroupMatchKey: "displayName"}.withDefaults()
	assert.Equal(t, DefaultExternalUserMatchKey, partial.UserMatchKey)
	assert.Equal(t, "displayName", partial.GroupMatchKey)
}

// TestGroupCarrierFailureKeepsDurableGrant guards the asymmetry between the two
// things GrantRoleToSubject can fail at.
//
// An unsupported subject kind is a real error and callers skip the subject. A
// carrier that will not build is not: the durable kube_group grant is the
// cluster's own record that this binding exists, and it has to survive. Callers
// read any error as "unsupported subject kind" and drop the subject entirely, so
// returning one here would silently delete access data over a failed
// optimization.
func TestGroupCarrierFailureKeepsDurableGrant(t *testing.T) {
	orig := makeCarrierBID
	t.Cleanup(func() { makeCarrierBID = orig })
	makeCarrierBID = func(bid.BID) (string, error) {
		return "", errors.New("synthetic bid failure")
	}

	subject := rbacv1.Subject{Kind: SubjectKindGroup, Name: "eng", APIGroup: RBACAPIGroup}
	grants, err := GrantRoleToSubject(context.Background(), subject, testRoleResource, "member", ExternalMatchConfig{})

	require.NoError(t, err, "a carrier failure must not surface as an error: callers read it as an unsupported subject kind and skip the subject")
	require.Len(t, grants, 1, "the durable grant must survive on its own")
	assert.Empty(t, carrierGrants(grants), "no carrier should be emitted when it cannot be built")
	assert.Equal(t, ResourceTypeKubeGroup.Id, grants[0].GetPrincipal().GetId().GetResourceType())
	assert.Equal(t, "eng", grants[0].GetPrincipal().GetId().GetResource())
}
