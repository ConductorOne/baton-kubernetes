package connector

import (
	"fmt"
	"sort"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
)

// objectPermissionSets is what an object of each modelled type can carry: every
// permission Kubernetes can authorize against one object of that kind.
//
// Fixed and known ahead of time, rather than read from the cluster or from its
// RBAC rules. An entitlement is a capability and a grant is who holds it, so
// "nobody can delete this pod" is a reviewable fact rather than a missing row,
// and an entitlement that came and went with the rules would churn every C1
// object referencing it — a campaign, a request, a policy.
//
// The set is (object-addressable verb) x (the resource and each of its
// subresources), which is the tuple the API server's authorizer evaluates.
// Collection verbs are absent by construction: list, watch and deletecollection
// address a collection rather than any member of it, so they belong on the
// api_resource target instead. create appears only for subresources — creating
// an object cannot be authorized by name, but creating a subresource can, which
// is what `kubectl exec mypod` is.
//
// impersonate on a ServiceAccount is here and nowhere in the cluster's discovery
// document: it authorizes an action rather than naming an endpoint, so discovery
// never reports it.
var objectPermissionSets = map[string][]string{
	ResourceTypePod.Id: objectSlugs(
		newSubresource("", verbGet, verbUpdate, verbPatch, verbDelete),
		newSubresource("attach", verbCreate, verbGet),
		newSubresource("binding", verbCreate),
		newSubresource("ephemeralcontainers", verbGet, verbPatch, verbUpdate),
		newSubresource("eviction", verbCreate),
		newSubresource("exec", verbCreate, verbGet),
		newSubresource("log", verbGet),
		newSubresource("portforward", verbCreate, verbGet),
		newSubresource("proxy", verbCreate, verbDelete, verbGet, verbPatch, verbUpdate),
		newSubresource("status", verbGet, verbPatch, verbUpdate),
	),
	ResourceTypeSecret.Id: objectSlugs(
		newSubresource("", verbGet, verbUpdate, verbPatch, verbDelete),
	),
	ResourceTypeConfigMap.Id: objectSlugs(
		newSubresource("", verbGet, verbUpdate, verbPatch, verbDelete),
	),
	ResourceTypeServiceAccount.Id: objectSlugs(
		newSubresource("", verbGet, verbUpdate, verbPatch, verbDelete, verbImpersonate),
		newSubresource("token", verbCreate),
	),
	ResourceTypeNode.Id: objectSlugs(
		newSubresource("", verbGet, verbUpdate, verbPatch, verbDelete),
		newSubresource("proxy", verbCreate, verbDelete, verbGet, verbPatch, verbUpdate),
		newSubresource("status", verbGet, verbPatch, verbUpdate),
	),
	ResourceTypeNamespace.Id: objectSlugs(
		newSubresource("", verbGet, verbUpdate, verbPatch, verbDelete),
		newSubresource("finalize", verbUpdate),
		newSubresource("status", verbGet, verbPatch, verbUpdate),
	),
	ResourceTypeDeployment.Id: objectSlugs(
		newSubresource("", verbGet, verbUpdate, verbPatch, verbDelete),
		newSubresource("scale", verbGet, verbPatch, verbUpdate),
		newSubresource("status", verbGet, verbPatch, verbUpdate),
	),
	ResourceTypeStatefulSet.Id: objectSlugs(
		newSubresource("", verbGet, verbUpdate, verbPatch, verbDelete),
		newSubresource("scale", verbGet, verbPatch, verbUpdate),
		newSubresource("status", verbGet, verbPatch, verbUpdate),
	),
	ResourceTypeDaemonSet.Id: objectSlugs(
		newSubresource("", verbGet, verbUpdate, verbPatch, verbDelete),
		newSubresource("status", verbGet, verbPatch, verbUpdate),
	),
}

// subresource is one endpoint of a resource and the verbs it accepts. The empty
// name is the resource itself.
type subresource struct {
	name  string
	verbs []string
}

func newSubresource(name string, verbs ...string) subresource {
	return subresource{name: name, verbs: verbs}
}

// objectSlugs flattens a type's endpoints into sorted entitlement slugs, with the
// wildcard that stands for a rule granting every verb.
func objectSlugs(subresources ...subresource) []string {
	slugs := []string{verbAll}
	for _, sub := range subresources {
		for _, verb := range sub.verbs {
			if sub.name == "" {
				slugs = append(slugs, verb)
				continue
			}
			slugs = append(slugs, fmt.Sprintf("%s:%s", verb, sub.name))
		}
	}
	sort.Strings(slugs)
	return slugs
}

// objectSlugsFor returns the entitlement slugs one (resource, verb) pair puts on
// an object of this type.
//
// Usually one. A wildcard verb on a subresource is the exception: a rule granting
// "*" on pods/exec permits every verb that endpoint accepts, and there is no
// `*:exec` entitlement to hang that on — nor should there be, since "create exec"
// and "get exec" say what the rule actually permits. So it expands to the
// subresource's declared verbs instead of collapsing to a slug nothing declares.
func objectSlugsFor(resourceTypeID, resource, verb string) []string {
	slug := objectEntitlementSlug(resource, verb)
	if verb != verbAll || !strings.Contains(resource, "/") {
		return []string{slug}
	}

	suffix := slug[len(verbAll):] // ":<subresource>"
	expanded := make([]string, 0, 4)
	for _, declared := range objectPermissionSets[resourceTypeID] {
		if declared != slug && strings.HasSuffix(declared, suffix) {
			expanded = append(expanded, declared)
		}
	}
	if len(expanded) == 0 {
		// Nothing declares that subresource; the caller's clamp drops it, and the
		// api_resource target still carries what the rule said.
		return []string{slug}
	}
	return expanded
}

// declaresObjectPermission reports whether a type declares this slug, so a grant
// can never reference an entitlement that was never declared.
func declaresObjectPermission(resourceTypeID, slug string) bool {
	for _, declared := range objectPermissionSets[resourceTypeID] {
		if declared == slug {
			return true
		}
	}
	return false
}

// staticObjectEntitlements declares an object type's permission set once, for the
// whole type.
//
// The syncer fans these templates out over every resource of the type
// (pkg/sync/syncer.go, syncStaticEntitlementsForResourceType), stamping each with
// its own entitlement ID, so one declaration becomes one entitlement per object
// without this connector visiting them. That is also why the display name cannot
// carry the object's name: the template is shared. In context — looking at the
// object — "delete" and "create exec" read correctly on their own.
func staticObjectEntitlements(resourceType *v2.ResourceType) []*v2.Entitlement {
	slugs := objectPermissionSets[resourceType.Id]
	rv := make([]*v2.Entitlement, 0, len(slugs))
	for _, slug := range slugs {
		rv = append(rv, entitlement.NewPermissionEntitlement(
			nil,
			slug,
			entitlement.WithDisplayName(slugLabel(slug)),
			entitlement.WithDescription(fmt.Sprintf("Permits %s on this %s",
				slugLabel(slug), resourceType.GetDisplayName())),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
				ResourceTypeRoleAssignment,
			),
		))
	}
	return rv
}
