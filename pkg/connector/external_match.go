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
// Kubernetes authorizes identities it does not store: a User or Group subject is
// just a string an authenticator asserted, and the directory behind it is a
// different C1 app. A grant carrying a match annotation is a *carrier* — the SDK
// rewrites it onto the matching external principal, then deletes it.
//
// Deletion is unconditional, matched or not, so carriers are emitted *alongside*
// the durable kube_user / kube_group grant, never instead of it. The durable
// grant is unannotated and always survives, which is what keeps group access
// attestable when a group matches nothing. Carriers ride the placeholder user and
// group resource types, which nothing syncs; the SDK exempts match-annotated
// grants from the usual unsynced-principal drop.
//
// Each carrier declares both strategies, since which one fits depends on the
// directory: MatchID for subjects that are already the external resource's ID,
// and a profile-key match for name- or address-shaped subjects. The SDK tries
// both, and honors only the first annotation of each type.
//
// ServiceAccounts are never carriers — they are real cluster objects with no
// directory counterpart.

// Default profile keys for the key/value match strategy. Both are overridable
// per deployment; the SDK also resolves "email" against a user's trait email
// addresses, not just a profile field of that name.
const (
	DefaultExternalUserMatchKey  = "email"
	DefaultExternalGroupMatchKey = "display_name"
)

// externalGroupMemberEntitlement is the entitlement a matched group expands
// through. It must be the last segment of an entitlement ID the identity source
// really emitted — the SDK looks up NewEntitlementID(matchedPrincipal, slug) as
// an exact string and drops the expansion on NotFound. Read the source's
// entitlement *ID*, not its Slug field; they can disagree. EntitlementIds is a
// list, so a second slug can be added if a source needs a different one.
const externalGroupMemberEntitlement = "members"

// makeCarrierBID is a seam. bid.MakeBid cannot fail for the inputs built here —
// the carrier resource always has both a type and a non-empty id — so the
// error branch below is only reachable from tests, which is exactly why it
// needs one: the branch must keep the durable grant, and nothing else proves
// it does.
var makeCarrierBID = bid.MakeBid

// ExternalMatchConfig names the profile keys a Kubernetes subject is matched on.
// The zero value is usable and takes the defaults; nothing here turns matching
// on or off.
type ExternalMatchConfig struct {
	UserMatchKey  string
	GroupMatchKey string
}

// withDefaults fills unset fields so a partial or zero struct still works.
func (c ExternalMatchConfig) withDefaults() ExternalMatchConfig {
	if c.UserMatchKey == "" {
		c.UserMatchKey = DefaultExternalUserMatchKey
	}
	if c.GroupMatchKey == "" {
		c.GroupMatchKey = DefaultExternalGroupMatchKey
	}
	return c
}

// userCarrierGrant returns the carrier for a User subject, or nil if unnamed.
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

// groupCarrierGrant returns the carrier for a Group subject, or nil if unnamed.
//
// GrantExpandable is what resolves a matched group to its members. Its
// entitlement must name the *carrier* resource: the SDK finds the expansion by
// the grant principal's bid, then re-mints the slug against whatever matched.
func (c ExternalMatchConfig) groupCarrierGrant(resource *v2.Resource, entName string, subjectName string) (*v2.Grant, error) {
	if subjectName == "" {
		return nil, nil
	}
	cfg := c.withDefaults()
	carrier := GenerateResourceForGrant(subjectName, ResourceTypeGroup.Id)

	memberBID, err := makeCarrierBID(entitlement.NewAssignmentEntitlement(carrier, externalGroupMemberEntitlement))
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
			// Shallow: the source's own connector already syncs nested
			// membership. ResourceTypeIds is left unset (unfiltered) because
			// the source's resource type IDs are not knowable from here.
			&v2.GrantExpandable{
				EntitlementIds: []string{memberBID},
				Shallow:        true,
			},
		),
	), nil
}
