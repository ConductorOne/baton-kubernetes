package connector

import (
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/bid"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
)

// External identity matching ("baton-id").
//
// A Kubernetes cluster authorizes principals it does not store. A User or Group
// subject in an RBAC binding is only a string some authenticator asserted — an
// OIDC claim, an x509 CN or O= field, an Entra object ID, an IAM ARN — and the
// directory that knows who that principal actually is belongs to a different C1
// app. That is why this connector cannot expand a group into people on its own,
// and why review evidence has always needed a second, federated source.
//
// The SDK bridges the two with match annotations. A grant carrying one is a
// *carrier*: during SyncExternalResourcesOp the syncer rewrites it onto every
// matching principal from the configured identity source and then deletes the
// original — see baton-sdk pkg/sync/syncer.go processGrantsWithExternalPrincipals.
// Deletion is unconditional, matched or not, so a carrier is not a safe place to
// keep cluster-level evidence: a group that resolves to nothing would vanish
// from the review entirely. This connector therefore emits a carrier *alongside*
// the durable kube_user / kube_group grant rather than instead of it. The durable
// grant carries no annotation, so it always survives and stays attestable at the
// group level; the carrier is what reaches the directory.
//
// Carriers ride on the placeholder user and group resource types, which no
// syncer ever lists. That is deliberate and the SDK sanctions it: a grant whose
// principal type was never synced is normally dropped at ingest, and the
// exemption is precisely a match annotation ("External match annotations own
// placeholder principals" — pkg/sync/ingest_filter.go). Keeping carriers off
// kube_user / kube_group also keeps the two grants distinct, since a grant's
// identity is (principal, entitlement) and reusing the principal would collapse
// them into one.
//
// Every carrier declares both available strategies, because which one fits is a
// property of the directory rather than of Kubernetes, and one connector build
// serves clusters federated against different ones:
//
//   - ExternalResourceMatchID matches the external resource's own ID, for
//     directories whose IDs Kubernetes uses verbatim (Entra group object IDs,
//     IAM role ARNs).
//   - ExternalResourceMatch matches a profile key, for the OIDC case where the
//     subject is a human-readable name or address.
//
// The SDK attempts both: its ID and key/value branches are sequential, not
// exclusive, so an unmatched strategy costs nothing and the pair of them covers
// both federation styles without per-cluster configuration. Only one annotation
// of each type is honored, since the SDK reads them with annotations.Pick, which
// returns the first of a given type — hence one configurable key per subject
// kind rather than a list. The group membership entitlement a match expands
// through is not configurable either, for a different reason: it is a property
// of the identity source, and this connector federates against one.
//
// ServiceAccounts are never carriers. A ServiceAccount is a real object in the
// cluster, synced as its own resource, and has no directory counterpart to
// match against.

// Default profile keys for the key/value match strategy.
const (
	// DefaultExternalUserMatchKey is "email" because Kubernetes usernames from
	// an OIDC issuer are conventionally email addresses, and because the SDK
	// special-cases this key: it matches a user's trait email addresses as well
	// as a profile field of that name, so it resolves against directories that
	// expose the address either way. Entra-federated clusters, whose usernames
	// are UPNs, should set "userPrincipalName" instead.
	DefaultExternalUserMatchKey = "email"

	// DefaultExternalGroupMatchKey is "display_name": the profile key Microsoft
	// Entra publishes a group's human-readable name under, and Entra is the
	// identity source this connector is federated against in practice.
	//
	// A Kubernetes group subject is a name on every platform except AKS, where
	// it is an Entra object GUID — and the GUID is handled by the ID strategy
	// instead, so this key only ever has to serve the name case. That includes
	// on-premises clusters whose subjects are AD group names: those groups reach
	// C1 through Entra as synced groups, under the same display_name, so the
	// directory's own connector never has to be the match target.
	//
	// Set this to whatever key a different identity source uses. Active
	// Directory, if matched directly rather than through Entra, carries the name
	// in "sAMAccountName" and has no display_name at all.
	DefaultExternalGroupMatchKey = "display_name"
)

// externalGroupMemberEntitlement is the entitlement a matched external group's
// membership expands through.
//
// It has to be the last segment of an entitlement ID the identity source
// actually emitted: the SDK re-mints NewEntitlementID(matchedPrincipal, slug)
// and looks that exact string up in the store, where the external app's
// entitlements were copied verbatim, then drops the expansion on NotFound.
//
// "members" is Microsoft Entra's, which is the identity source this connector
// federates against — the same assumption DefaultExternalGroupMatchKey rests on.
// Note that Entra is also the one connector where this disagrees with its own
// Slug field: it builds the ID by hand as "group:<id>:members" while declaring
// Slug "member", and the ID is what the lookup uses. Reading the Slug is how you
// get this wrong.
//
// Directories that construct the entitlement the ordinary way — Okta, Google
// Workspace, Active Directory, JumpCloud, via NewAssignmentEntitlement(r,
// "member") — need "member" instead. Naming both here would cover them, at the
// price of an SDK error log per carrier for whichever one misses; that trade is
// only worth making if this connector stops being Entra-federated.
const externalGroupMemberEntitlement = "members"

// ExternalMatchConfig names the directory-side fields a Kubernetes subject is
// matched on. Its zero value is usable and means "the defaults above": the
// connector always emits carriers, so no field here switches the feature on or
// off, they only tune what the carriers claim to match.
type ExternalMatchConfig struct {
	// UserMatchKey is the profile key an external user is matched on.
	UserMatchKey string
	// GroupMatchKey is the profile key an external group is matched on.
	GroupMatchKey string
}

// withDefaults fills unset fields, so callers that construct the struct
// partially — or not at all — still produce usable carriers.
func (c ExternalMatchConfig) withDefaults() ExternalMatchConfig {
	if c.UserMatchKey == "" {
		c.UserMatchKey = DefaultExternalUserMatchKey
	}
	if c.GroupMatchKey == "" {
		c.GroupMatchKey = DefaultExternalGroupMatchKey
	}
	return c
}

// userCarrierGrant returns the carrier grant for a User subject, or nil when the
// subject name is empty and there is nothing to match on.
func (c ExternalMatchConfig) userCarrierGrant(resource *v2.Resource, entName string, subjectName string) *v2.Grant {
	if subjectName == "" {
		return nil
	}
	cfg := c.withDefaults()
	carrier := GenerateResourceForGrant(subjectName, ResourceTypeUser.Id)
	return grant.NewGrant(
		resource,
		entName,
		carrier,
		grant.WithAnnotation(
			&v2.ExternalResourceMatchID{Id: subjectName},
			&v2.ExternalResourceMatch{
				Key:          cfg.UserMatchKey,
				Value:        subjectName,
				ResourceType: v2.ResourceType_TRAIT_USER,
			},
		),
	)
}

// groupCarrierGrant returns the carrier grant for a Group subject, or nil when
// the subject name is empty.
//
// The GrantExpandable annotation is what turns a matched directory group into
// its individual members. Its entitlement ID must name the *carrier* resource:
// the syncer looks the expansion up by the grant principal's bid and then
// re-mints the same slug against whichever external principal matched, so
// pointing it at the carrier is how the remap finds it at all.
func (c ExternalMatchConfig) groupCarrierGrant(resource *v2.Resource, entName string, subjectName string) (*v2.Grant, error) {
	if subjectName == "" {
		return nil, nil
	}
	cfg := c.withDefaults()
	carrier := GenerateResourceForGrant(subjectName, ResourceTypeGroup.Id)

	memberBID, err := bid.MakeBid(entitlement.NewAssignmentEntitlement(carrier, externalGroupMemberEntitlement))
	if err != nil {
		return nil, fmt.Errorf("baton-kubernetes: failed to build %q entitlement bid for group %q: %w",
			externalGroupMemberEntitlement, subjectName, err)
	}

	return grant.NewGrant(
		resource,
		entName,
		carrier,
		grant.WithAnnotation(
			&v2.ExternalResourceMatchID{Id: subjectName},
			&v2.ExternalResourceMatch{
				Key:          cfg.GroupMatchKey,
				Value:        subjectName,
				ResourceType: v2.ResourceType_TRAIT_GROUP,
			},
			// Shallow: the directory's own connector already syncs nested group
			// membership, so expanding one level onto that group's member
			// entitlement reaches every account without this connector
			// re-walking a hierarchy it cannot see.
			//
			// ResourceTypeIds is deliberately unset, which means unfiltered.
			// Narrowing it would require naming the identity source's own
			// resource type IDs, and those are that connector's private
			// vocabulary — this connector cannot know whether its accounts are
			// called "user", "account", or something else, and guessing wrong
			// filters the expansion down to nothing.
			&v2.GrantExpandable{
				EntitlementIds: []string{memberBID},
				Shallow:        true,
			},
		),
	), nil
}
