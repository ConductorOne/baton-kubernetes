package connector

import (
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

// isCarrier reports whether a grant is an external-match carrier. Carrying a
// match annotation is what makes it one — that is the property the SDK keys on
// too, so testing for it beats inferring from the principal's resource type.
func isCarrier(g *v2.Grant) bool {
	annos := annotations.Annotations(g.GetAnnotations())
	return annos.ContainsAny(
		&v2.ExternalResourceMatchAll{},
		&v2.ExternalResourceMatch{},
		&v2.ExternalResourceMatchID{},
	)
}

// durableGrants returns only the grants that stand on their own: the ones whose
// principal is a resource this connector actually syncs. Every User and Group
// subject also yields a carrier (see external_match.go), so a test about binding
// scope, subject dedup, or cache lifetime would otherwise be counting carriers
// along with the access it means to measure.
func durableGrants(grants []*v2.Grant) []*v2.Grant {
	out := make([]*v2.Grant, 0, len(grants))
	for _, g := range grants {
		if !isCarrier(g) {
			out = append(out, g)
		}
	}
	return out
}

// carrierGrants is durableGrants' complement, for the tests that are about
// carriers.
func carrierGrants(grants []*v2.Grant) []*v2.Grant {
	out := make([]*v2.Grant, 0, len(grants))
	for _, g := range grants {
		if isCarrier(g) {
			out = append(out, g)
		}
	}
	return out
}

// pickMatchID returns the ExternalResourceMatchID on a grant, failing the test
// if it carries none.
func pickMatchID(t *testing.T, g *v2.Grant) *v2.ExternalResourceMatchID {
	t.Helper()
	annos := annotations.Annotations(g.GetAnnotations())
	got := &v2.ExternalResourceMatchID{}
	ok, err := annos.Pick(got)
	require.NoError(t, err)
	require.True(t, ok, "grant carries no ExternalResourceMatchID")
	return got
}

// pickMatch returns the key/value ExternalResourceMatch on a grant, failing the
// test if it carries none.
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

// TestUserSubjectEmitsDurableAndCarrier verifies a User subject produces both
// grants: the durable one that survives with no identity source configured, and
// the carrier that reaches the directory. The durable grant must carry no match
// annotation, or the SDK would delete it along with the carrier and the user's
// access would disappear from the review entirely.
func TestUserSubjectEmitsDurableAndCarrier(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindUser, Name: "alice@example.com", APIGroup: RBACAPIGroup}

	grants, err := GrantRoleToSubject(subject, testRoleResource, "member", ExternalMatchConfig{})
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

// TestGroupSubjectEmitsDurableAndCarrier verifies the same for a Group subject,
// plus the expansion annotation that turns a matched directory group into the
// accounts inside it.
func TestGroupSubjectEmitsDurableAndCarrier(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindGroup, Name: "SCRUM-HPC-ADMIN", APIGroup: RBACAPIGroup}

	grants, err := GrantRoleToSubject(subject, testRoleResource, "member", ExternalMatchConfig{})
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

// TestGroupCarrierExpandableTargetsItsOwnPrincipal pins the invariant the SDK's
// remap depends on: it looks the expansion up by the bid of the grant's
// principal, then re-mints the same slug against whichever external principal
// matched. An expandable entitlement naming any other resource is silently
// ignored, and the group would match but never expand to its members.
func TestGroupCarrierExpandableTargetsItsOwnPrincipal(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindGroup, Name: "prod-developer", APIGroup: RBACAPIGroup}

	grants, err := GrantRoleToSubject(subject, testRoleResource, "member", ExternalMatchConfig{})
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

// TestCarrierAndDurableGrantIDsDiffer verifies the two grants for one subject
// are distinct objects. A grant's identity is (principal, entitlement), so
// putting the carrier on the same principal as the durable grant would collapse
// them into one and the durable grant would be lost.
func TestCarrierAndDurableGrantIDsDiffer(t *testing.T) {
	for _, subject := range []rbacv1.Subject{
		{Kind: SubjectKindUser, Name: "alice", APIGroup: RBACAPIGroup},
		{Kind: SubjectKindGroup, Name: "admins", APIGroup: RBACAPIGroup},
	} {
		t.Run(subject.Kind, func(t *testing.T) {
			grants, err := GrantRoleToSubject(subject, testRoleResource, "member", ExternalMatchConfig{})
			require.NoError(t, err)
			require.Len(t, grants, 2)
			assert.NotEqual(t, grants[0].GetId(), grants[1].GetId())
		})
	}
}

// TestServiceAccountEmitsNoCarrier verifies a ServiceAccount stays a single
// grant. It is a real object in the cluster with no directory counterpart, so a
// carrier for it could only ever match the wrong thing.
func TestServiceAccountEmitsNoCarrier(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindServiceAccount, Name: "argo", Namespace: "argocd"}

	grants, err := GrantRoleToSubject(subject, testRoleResource, "member", ExternalMatchConfig{})
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, ResourceTypeServiceAccount.Id, grants[0].GetPrincipal().GetId().GetResourceType())
	assert.Equal(t, "argocd/argo", grants[0].GetPrincipal().GetId().GetResource())
	assert.Empty(t, carrierGrants(grants))
}

// TestSystemSubjectsStillSkipped verifies adding carriers did not widen which
// subjects the connector emits at all. Kubernetes' built-in system: principals
// are cluster machinery, not identities any directory knows about.
func TestSystemSubjectsStillSkipped(t *testing.T) {
	for _, subject := range []rbacv1.Subject{
		{Kind: SubjectKindGroup, Name: "system:masters", APIGroup: RBACAPIGroup},
		{Kind: SubjectKindUser, Name: "system:kube-controller-manager", APIGroup: RBACAPIGroup},
	} {
		t.Run(subject.Name, func(t *testing.T) {
			grants, err := GrantRoleToSubject(subject, testRoleResource, "member", ExternalMatchConfig{})
			require.Error(t, err)
			assert.Empty(t, grants)
		})
	}
}

// TestNonRBACAPIGroupSubjectsSkipped verifies a User or Group subject from an
// unexpected apiGroup is still rejected rather than turned into a carrier that
// would claim a directory match on an identity Kubernetes did not authenticate
// through RBAC.
func TestNonRBACAPIGroupSubjectsSkipped(t *testing.T) {
	subject := rbacv1.Subject{Kind: SubjectKindUser, Name: "alice", APIGroup: "example.com"}

	grants, err := GrantRoleToSubject(subject, testRoleResource, "member", ExternalMatchConfig{})
	require.Error(t, err)
	assert.Empty(t, grants)
}

// TestExternalMatchConfigOverrides verifies the configured keys reach the
// annotations, which is what lets one connector build serve clusters federated
// against different directories.
func TestExternalMatchConfigOverrides(t *testing.T) {
	cfg := ExternalMatchConfig{
		UserMatchKey:  "userPrincipalName",
		GroupMatchKey: "displayName",
	}

	userGrants, err := GrantRoleToSubject(
		rbacv1.Subject{Kind: SubjectKindUser, Name: "alice@corp.example", APIGroup: RBACAPIGroup},
		testRoleResource, "member", cfg)
	require.NoError(t, err)
	userCarrier := carrierGrants(userGrants)
	require.Len(t, userCarrier, 1)
	assert.Equal(t, "userPrincipalName", pickMatch(t, userCarrier[0]).GetKey())

	groupGrants, err := GrantRoleToSubject(
		rbacv1.Subject{Kind: SubjectKindGroup, Name: "eng", APIGroup: RBACAPIGroup},
		testRoleResource, "member", cfg)
	require.NoError(t, err)
	groupCarrier := carrierGrants(groupGrants)
	require.Len(t, groupCarrier, 1)
	assert.Equal(t, "displayName", pickMatch(t, groupCarrier[0]).GetKey())
}

// TestGroupCarrierUsesEntrasMemberEntitlement pins the slug to the one Microsoft
// Entra actually emits.
//
// The SDK looks up NewEntitlementID(matchedPrincipal, slug) as an exact string
// against entitlements copied verbatim from the identity source, and Entra builds
// its group membership ID by hand as "group:<id>:members" while declaring Slug
// "member". Taking the Slug field at face value yields "member", which resolves
// to nothing and silently drops the expansion.
func TestGroupCarrierUsesEntrasMemberEntitlement(t *testing.T) {
	grants, err := GrantRoleToSubject(
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

// TestExternalMatchConfigDefaults verifies the zero value is usable, since the
// downstream connectors that build this connector as a library may not set it
// and a partial struct must not produce a carrier with an empty match key.
func TestExternalMatchConfigDefaults(t *testing.T) {
	got := ExternalMatchConfig{}.withDefaults()
	assert.Equal(t, DefaultExternalUserMatchKey, got.UserMatchKey)
	assert.Equal(t, DefaultExternalGroupMatchKey, got.GroupMatchKey)

	partial := ExternalMatchConfig{GroupMatchKey: "displayName"}.withDefaults()
	assert.Equal(t, DefaultExternalUserMatchKey, partial.UserMatchKey)
	assert.Equal(t, "displayName", partial.GroupMatchKey)
}
