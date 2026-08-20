package connector

import (
	"context"
	"fmt"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	// coreAPIGroup is how the core group — the empty string in a rule — is
	// written in a class ID, which cannot carry an empty segment.
	coreAPIGroup = "core"
	// nonResourceGroup stands in for the API group of a nonResourceURLs rule.
	// It starts with an underscore, which an API group cannot (groups are DNS
	// subdomains), so it can never collide with a real group.
	nonResourceGroup = "_url"
	// clusterScopeID is the scope segment of a cluster-wide class ID. A
	// namespace can never be named "*", so a cluster-wide class can never
	// collide with a namespace-scoped one.
	clusterScopeID = "*"
	// roleMemberEntitlement is the namespaced Role's membership entitlement,
	// which is also the expansion source for permissions a Role confers.
	roleMemberEntitlement = "member"
	// systemPrefix marks Kubernetes' own control-plane roles and subjects.
	systemPrefix = "system:"
)

// Profile keys for permission class resources.
const (
	profileKeyAPIGroup     = "apiGroup"
	profileKeyAPIResource  = "apiResource"
	profileKeyResourceName = "resourceName"
)

// API resource plurals — the names rules use — for the kinds this connector
// models objects of.
// appsAPIGroup is the group of the workload controllers this connector models.
const appsAPIGroup = "apps"

const (
	pluralPods            = "pods"
	pluralSecrets         = "secrets"
	pluralConfigMaps      = "configmaps"
	pluralDeployments     = "deployments"
	pluralStatefulSets    = "statefulsets"
	pluralDaemonSets      = "daemonsets"
	pluralNodes           = "nodes"
	pluralNamespaces      = "namespaces"
	pluralServiceAccounts = "serviceaccounts"
)

// objectVerbs are the verbs that address one object, whatever the resource.
//
// This is the same question as "can a resourceNames rule gate it": Kubernetes
// matches resourceNames only when the request carries the target's name, and it
// carries a name only when the verb addresses an object. "get" names it in the
// path; "list" and "watch" ask for a collection and "deletecollection" for all of
// one, so neither identifies an object nor matches a resourceNames rule.
var objectVerbs = map[string]bool{
	verbGet:         true,
	verbUpdate:      true,
	verbPatch:       true,
	verbDelete:      true,
	verbBind:        true,
	verbEscalate:    true,
	verbImpersonate: true,
	verbAll:         true,
}

// addressesObject reports whether (verb, resource) identifies a single object.
//
// "create" is the one that depends on the resource. Creating an object cannot be
// restricted by name — the name is in the request body, not the path, which is
// the documented reason resourceNames does not gate create. Creating a
// *subresource* can: `kubectl exec mypod` is a create on pods/exec whose request
// path carries mypod, so `{resources: [pods/exec], resourceNames: [mypod],
// verbs: [create]}` is a real and widely used way to restrict exec to one pod.
func addressesObject(verb, resource string) bool {
	if verb == verbCreate {
		return strings.Contains(resource, "/")
	}
	return objectVerbs[verb]
}

// instanceResourceTypes maps an API resource plural onto the resource type this
// connector models its objects with, for the resourceNames rules that really do
// target one object.
//
// Deliberately excludes roles and clusterroles: those resources carry
// membership entitlements whose emission the sparse model suppresses, so
// hanging permission entitlements on them too would make what a review sees
// depend on --use-role-assignments. A rule naming them by name is still
// recorded at class level.
var instanceResourceTypes = map[string]*v2.ResourceType{
	pluralPods:            ResourceTypePod,
	pluralSecrets:         ResourceTypeSecret,
	pluralConfigMaps:      ResourceTypeConfigMap,
	pluralDeployments:     ResourceTypeDeployment,
	pluralStatefulSets:    ResourceTypeStatefulSet,
	pluralDaemonSets:      ResourceTypeDaemonSet,
	pluralNodes:           ResourceTypeNode,
	pluralNamespaces:      ResourceTypeNamespace,
	pluralServiceAccounts: ResourceTypeServiceAccount,
}

// clusterScopedInstanceTypes are the instance types whose objects are not
// namespaced, so a resourceNames rule identifies them by bare name.
var clusterScopedInstanceTypes = map[string]bool{
	ResourceTypeNode.Id:      true,
	ResourceTypeNamespace.Id: true,
}

// instanceKind is one modelled object type and the API resource it is, so a rule
// can be matched against it.
type instanceKind struct {
	group    string
	plural   string
	resource *v2.ResourceType
}

// instanceKinds is instanceResourceTypes in matchable form. The group is known
// statically for every type the connector syncs — a Deployment is always
// apps/deployments — so nothing has to be inferred from the rule side.
var instanceKinds = []instanceKind{
	{"", pluralPods, ResourceTypePod},
	{"", pluralSecrets, ResourceTypeSecret},
	{"", pluralConfigMaps, ResourceTypeConfigMap},
	{"", pluralNodes, ResourceTypeNode},
	{"", pluralNamespaces, ResourceTypeNamespace},
	{"", pluralServiceAccounts, ResourceTypeServiceAccount},
	{appsAPIGroup, pluralDeployments, ResourceTypeDeployment},
	{appsAPIGroup, pluralStatefulSets, ResourceTypeStatefulSet},
	{appsAPIGroup, pluralDaemonSets, ResourceTypeDaemonSet},
}

// matches reports whether a rule's (apiGroup, resource) covers this kind.
//
// Matching is not equality, because the wildcards are on the rule side: a rule
// may name the group, the resource, or both as "*". Conversely a rule naming
// apps/deployments does not cover extensions/deployments, which is why the group
// is compared at all — that rule is dead since 1.16 and reaches nothing.
func (k instanceKind) matches(ruleGroup, ruleResource string) bool {
	if ruleGroup != verbAll && ruleGroup != k.group {
		return false
	}
	base := ruleResource
	if slash := strings.Index(ruleResource, "/"); slash >= 0 {
		base = ruleResource[:slash]
	}
	return base == verbAll || base == k.plural
}

// objectEntitlementSlug names the entitlement a (resource, verb) pair puts on an
// object.
//
// A plain resource contributes the verb itself. A subresource contributes both,
// because the verb alone would be misleading: "create" on a Pod would read as
// permission to create that pod, when the rule actually grants a shell into it.
// `create:exec`, `get:log` and `update:scale` say what the rule says.
func objectEntitlementSlug(resource, verb string) string {
	if slash := strings.Index(resource, "/"); slash >= 0 {
		return fmt.Sprintf("%s:%s", verb, resource[slash+1:])
	}
	return verb
}

// ruleSource is where a rule came from: the scope it was bound in, the resource a
// grant should hang off, and whether that resource is part of the control plane.
type ruleSource struct {
	principal    principalRef
	scopeType    string
	scopeID      string
	controlPlane bool
}

// isControlPlaneRole reports whether a role belongs to Kubernetes' own control
// plane, which names them all under the system: prefix.
//
// Prefix rather than the substring match GrantRoleToSubject uses on subjects: a
// role legitimately named "acme-system:reader" is not the control plane, and at
// the object layer this decides whether permissions are reported at all.
func isControlPlaneRole(name string) bool {
	return strings.HasPrefix(name, systemPrefix)
}

// objectScope keys the permissions every object of one type carries within one
// scope. Objects are not known when the index is built, so this is what a
// builder looks up per object it lists.
type objectScope struct {
	resourceType string
	scopeType    string
	scopeID      string
}

// permissionClass is one authorization target: an API resource at a scope,
// optionally narrowed to a single object name.
//
// This is the tuple the API server's own authorizer evaluates — (apiGroup,
// resource, name, namespace) — rather than a set of objects, which is what makes
// it able to carry pods/exec: that is a real API resource with no objects at all,
// so nothing about it can be expressed as a set of pods.
//
// resource keeps any subresource ("pods/exec") and may be the wildcard "*".
// group is the raw rule value, so the core group is the empty string here and
// only becomes "core" in an ID.
//
// name is set only for a resourceNames rule, and it is what keeps such a rule
// from overstating: a role that can get one named Secret must not appear to hold
// "get secrets" for the whole namespace. The narrowed target carries the
// permission whether or not the object exists or its resource type is synced —
// naming an object that has not been created yet is legal RBAC — while the
// instance edge on the real object (see addNamedObjects) is what a reviewer
// looking at that object finds.
type permissionClass struct {
	group     string
	resource  string
	name      string
	scopeType string
	scopeID   string
}

// less orders classes for paging. Shared by the sort and the resume search so
// the two can never disagree about what "the next class" means.
func (c permissionClass) less(other permissionClass) bool {
	if c.scopeType != other.scopeType {
		return c.scopeType < other.scopeType
	}
	if c.scopeID != other.scopeID {
		return c.scopeID < other.scopeID
	}
	if c.group != other.group {
		return c.group < other.group
	}
	if c.resource != other.resource {
		return c.resource < other.resource
	}
	return c.name < other.name
}

// objectID builds the class resource's object ID.
//
// Nothing parses it back — Entitlements and Grants look the class up by ID in
// the index — but it stays legible, and it carries the API group because a
// resource plural is not unique: a stock cluster serves events in both the core
// and events.k8s.io groups, ClusterRole edit names deployments in both apps and
// the long-dead extensions, and CRDs collide freely (gateways exists in both
// networking.istio.io and gateway.networking.k8s.io).
// The optional object name is a third colon-separated segment. Nothing it can
// contain is ambiguous: an API group and an object name are both DNS names and a
// resource plural is a lowercase word, so none of the three may hold a colon.
func (c permissionClass) objectID() string {
	group := c.group
	if group == "" {
		group = coreAPIGroup
	}
	if c.name != "" {
		return fmt.Sprintf("%s:%s:%s@%s", group, c.resource, c.name, c.scopeID)
	}
	return fmt.Sprintf("%s:%s@%s", group, c.resource, c.scopeID)
}

// label names the API resource for a human, hiding the group for core kinds and
// for non-resource URLs, which have none.
func (c permissionClass) label() string {
	label := c.resource
	if c.group != "" && c.group != nonResourceGroup {
		label = fmt.Sprintf("%s (%s)", c.resource, c.group)
	}
	if c.name != "" {
		// Quoted so the last token reads as one object's name rather than as
		// another part of the resource path.
		return fmt.Sprintf("%s %q", label, c.name)
	}
	return label
}

func (c permissionClass) displayName() string {
	if c.scopeType == ResourceTypeCluster.Id {
		return fmt.Sprintf("%s cluster-wide", c.label())
	}
	return fmt.Sprintf("%s in %s", c.label(), c.scopeID)
}

func (c permissionClass) description() string {
	if c.scopeType == ResourceTypeCluster.Id {
		return fmt.Sprintf("RBAC permissions on %s in every namespace", c.label())
	}
	return fmt.Sprintf("RBAC permissions on %s in namespace %s", c.label(), c.scopeID)
}

// namedObject identifies one real object a resourceNames rule targets.
type namedObject struct {
	resourceType string
	objectID     string
}

// principalRef is the resource a permission grant hangs off, plus the
// entitlement the SDK should expand it through.
//
// expandVia is empty when nothing should be expanded. Otherwise it names an
// entitlement on this same resource: grant expansion requires the expandable
// entitlement to live on the grant's own principal, and baton-sdk's
// loadEntitlementGraph fails the sync outright when it does not
// (pkg/sync/syncer.go, "source entitlement resource id did not match grant
// principal id").
type principalRef struct {
	resourceType string
	resourceID   string
	expandVia    string
}

func (p principalRef) less(other principalRef) bool {
	if p.resourceType != other.resourceType {
		return p.resourceType < other.resourceType
	}
	if p.resourceID != other.resourceID {
		return p.resourceID < other.resourceID
	}
	return p.expandVia < other.expandVia
}

func (p principalRef) resourceRef() *v2.ResourceId {
	return &v2.ResourceId{ResourceType: p.resourceType, Resource: p.resourceID}
}

// PermissionIndex holds every rule-backed permission edge in the cluster for one
// sync: which authorization targets exist, which verbs each one carries, and
// which role-shaped resource confers them.
type PermissionIndex struct {
	classes map[permissionClass]map[string][]principalRef
	byID    map[string]permissionClass
	sorted  []permissionClass
	named   map[namedObject]map[string][]principalRef
	// objects holds what every object of a type carries within one scope, for
	// the object-addressable half of each rule. Objects are not known when the
	// index is built, so a builder looks this up per object it lists.
	objects map[objectScope]map[string][]principalRef
	// inertRules counts rules that can never authorize anything in the scope
	// they were bound in, and so produce no edge.
	inertRules int
}

// Classes returns this sync's classes in a stable order, so paging over them is
// repeatable even though the index is rebuilt from live cluster state.
func (i *PermissionIndex) Classes() []permissionClass {
	if i == nil {
		return nil
	}
	return i.sorted
}

// Class resolves a class resource's object ID back to the class.
func (i *PermissionIndex) Class(objectID string) (permissionClass, bool) {
	if i == nil {
		return permissionClass{}, false
	}
	class, ok := i.byID[objectID]
	return class, ok
}

// Verbs returns the verbs a class carries, sorted.
func (i *PermissionIndex) Verbs(class permissionClass) []string {
	if i == nil {
		return nil
	}
	verbs := make([]string, 0, len(i.classes[class]))
	for verb := range i.classes[class] {
		verbs = append(verbs, verb)
	}
	sort.Strings(verbs)
	return verbs
}

// Principals returns the resources conferring one verb on one class.
func (i *PermissionIndex) Principals(class permissionClass, verb string) []principalRef {
	if i == nil {
		return nil
	}
	return i.classes[class][verb]
}

// objectPermissions returns what every object of one type carries in one scope,
// keyed by entitlement slug.
func (i *PermissionIndex) objectPermissions(scope objectScope) map[string][]principalRef {
	if i == nil {
		return nil
	}
	return i.objects[scope]
}

// namedVerbs returns the verbs a resourceNames rule confers on one real object,
// keyed by verb, or nil when no rule names it.
func (i *PermissionIndex) namedVerbs(object namedObject) map[string][]principalRef {
	if i == nil {
		return nil
	}
	return i.named[object]
}

// PermissionIndexProvider resolves the permission index for one sync.
//
// Declared as an interface for the same reason as BindingLister: the cloud
// connectors replace builders through WithCustomSyncers while still resolving
// through the shared, sync-scoped cache.
type PermissionIndexProvider interface {
	PermissionIndex(ctx context.Context, syncID string) (*PermissionIndex, error)
}

// permissionResolver hands a builder the permission grants for its own objects.
//
// Only grants: which permissions a type declares is fixed and known without ever
// reading the cluster (see object_permissions.go), so the entitlement side needs
// nothing from here. Grants are the half that depends on the cluster's rules.
//
// A nil resolver is tolerated so the capabilities builder, which has no client,
// can construct every syncer.
type permissionResolver struct {
	provider PermissionIndexProvider
}

// objectPermissions returns everything one object carries: the permissions every
// object of its type carries in its scope, plus any a resourceNames rule confers
// on it specifically.
//
// Cluster-wide rules are merged in for a namespaced object, because a
// ClusterRoleBinding reaches every namespace — including the one this object
// lives in.
func (r *permissionResolver) objectPermissions(
	ctx context.Context,
	syncID string,
	resourceType *v2.ResourceType,
	resource *v2.Resource,
) (map[string][]principalRef, error) {
	if r == nil || r.provider == nil {
		return nil, nil
	}
	index, err := r.provider.PermissionIndex(ctx, syncID)
	if err != nil {
		return nil, err
	}

	merged := map[string][]principalRef{}
	add := func(from map[string][]principalRef) {
		for slug, principals := range from {
			merged[slug] = append(merged[slug], principals...)
		}
	}

	add(index.objectPermissions(objectScope{
		resourceType: resourceType.Id,
		scopeType:    ResourceTypeCluster.Id,
		scopeID:      clusterScopeID,
	}))
	if namespace := objectNamespace(resource); namespace != "" {
		add(index.objectPermissions(objectScope{
			resourceType: resourceType.Id,
			scopeType:    ResourceTypeNamespace.Id,
			scopeID:      namespace,
		}))
	}
	add(index.namedVerbs(namedObject{
		resourceType: resourceType.Id,
		objectID:     resource.GetId().GetResource(),
	}))

	for slug := range merged {
		if !declaresObjectPermission(resourceType.Id, slug) {
			// The type declares a fixed set, so a grant outside it would point at
			// an entitlement nothing ever created. Reaching here means either the
			// subresource does not exist on this cluster — in which case the rule
			// authorizes nothing and dropping it is correct — or the table in
			// object_permissions.go has fallen behind a Kubernetes release.
			ctxzap.Extract(ctx).Debug("dropping permission the resource type does not declare",
				zap.String("resource_type", resourceType.Id),
				zap.String("slug", slug))
			delete(merged, slug)
			continue
		}
		merged[slug] = dedupePrincipals(merged[slug])
	}
	return merged, nil
}

// objectNamespace returns the namespace an object lives in, taken from its parent
// resource, or "" for a cluster-scoped object.
func objectNamespace(resource *v2.Resource) string {
	parent := resource.GetParentResourceId()
	if parent.GetResourceType() != ResourceTypeNamespace.Id {
		return ""
	}
	return parent.GetResource()
}

// objectGrants returns the grants matching objectEntitlements.
func objectGrants(
	ctx context.Context,
	resolver *permissionResolver,
	opts rs.SyncOpAttrs,
	resourceType *v2.ResourceType,
	resource *v2.Resource,
) ([]*v2.Grant, error) {
	permissions, err := resolver.objectPermissions(ctx, opts.SyncID, resourceType, resource)
	if err != nil {
		return nil, err
	}

	var rv []*v2.Grant
	for _, slug := range sortedSlugs(permissions) {
		for _, principal := range permissions[slug] {
			rv = append(rv, permissionGrant(resource, slug, principal))
		}
	}
	return rv, nil
}

// sortedSlugs orders entitlement slugs so two syncs of an unchanged cluster
// produce identical output.
func sortedSlugs(permissions map[string][]principalRef) []string {
	slugs := make([]string, 0, len(permissions))
	for slug := range permissions {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	return slugs
}

// slugLabel renders an entitlement slug for display: "get", "* (all verbs)", or
// for a subresource "create exec".
func slugLabel(slug string) string {
	verb, subresource, found := strings.Cut(slug, ":")
	if !found {
		return verbLabel(slug)
	}
	return fmt.Sprintf("%s %s", verbLabel(verb), subresource)
}

func dedupePrincipals(principals []principalRef) []principalRef {
	if len(principals) < 2 {
		return principals
	}
	seen := make(map[principalRef]struct{}, len(principals))
	out := make([]principalRef, 0, len(principals))
	for _, principal := range principals {
		if _, ok := seen[principal]; ok {
			continue
		}
		seen[principal] = struct{}{}
		out = append(out, principal)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].less(out[j]) })
	return out
}

// permissionGrant builds one permission grant, expandable through the
// principal's own membership entitlement so the identities holding the role
// inherit the permission.
//
// Shallow is deliberately left unset: a membership entitlement can itself be
// held by a group, and a connector that knows how to expand groups (the cloud
// ones do, through their own annotations) should carry the permission all the
// way to the users.
func permissionGrant(resource *v2.Resource, verb string, principal principalRef) *v2.Grant {
	var opts []grant.GrantOption
	if principal.expandVia != "" {
		opts = append(opts, grant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{fmt.Sprintf("%s:%s:%s",
				principal.resourceType, principal.resourceID, principal.expandVia)},
		}))
	}
	return grant.NewGrant(resource, verb, principal.resourceRef(), opts...)
}

// verbLabel renders a verb for display, spelling out the wildcard.
func verbLabel(verb string) string {
	if verb == verbAll {
		return "* (all verbs)"
	}
	return verb
}

// buildPermissionIndex derives every rule-backed permission edge in the cluster.
//
// Bindings drive it, not roles: a rule confers nothing until a binding places it
// in a scope, and the scope is what classes are keyed on. A role nobody binds
// therefore produces no edge — its rules stay visible as profile data on the
// role itself, which is what PR #46 added them for.
func buildPermissionIndex(
	ctx context.Context,
	client kubernetes.Interface,
	bindings BindingLister,
	syncID string,
	useRoleAssignments bool,
	includeControlPlane bool,
) (*PermissionIndex, error) {
	l := ctxzap.Extract(ctx)

	roleBindings, clusterRoleBindings, err := bindings.AllBindings(ctx, syncID)
	if err != nil {
		return nil, fmt.Errorf("failed to list bindings: %w", err)
	}
	clusterRoleRules, err := listClusterRoleRules(ctx, client)
	if err != nil {
		return nil, err
	}
	roleRules, err := listRoleRules(ctx, client)
	if err != nil {
		return nil, err
	}
	apiResources, err := discoverAPIResources(ctx, client)
	if err != nil {
		return nil, err
	}

	b := &permissionIndexBuilder{
		apiResources:        apiResources,
		includeControlPlane: includeControlPlane,
		classes:             map[permissionClass]map[string]map[principalRef]struct{}{},
		named:               map[namedObject]map[string]map[principalRef]struct{}{},
		objects:             map[objectScope]map[string]map[principalRef]struct{}{},
	}

	for _, crb := range clusterRoleBindings {
		if crb.RoleRef.Kind != RBACKindClusterRole {
			continue
		}
		rules, ok := clusterRoleRules[crb.RoleRef.Name]
		if !ok {
			// A binding may reference a cluster role that does not exist. Such
			// bindings are legal and inert, and role_assignment skips them for
			// the same reason.
			l.Debug("skipping binding with unresolvable roleRef",
				zap.String("binding", crb.Name),
				zap.String("cluster_role", crb.RoleRef.Name))
			continue
		}
		b.addRules(rules, ruleSource{
			principal:    clusterRolePrincipal(crb.RoleRef.Name, ResourceTypeCluster.Id, clusterScopeID, useRoleAssignments),
			scopeType:    ResourceTypeCluster.Id,
			scopeID:      clusterScopeID,
			controlPlane: isControlPlaneRole(crb.RoleRef.Name),
		})
	}

	for _, rb := range roleBindings {
		switch rb.RoleRef.Kind {
		case RBACKindClusterRole:
			rules, ok := clusterRoleRules[rb.RoleRef.Name]
			if !ok {
				l.Debug("skipping binding with unresolvable roleRef",
					zap.String("binding", rb.Name),
					zap.String("cluster_role", rb.RoleRef.Name))
				continue
			}
			b.addRules(rules, ruleSource{
				principal:    clusterRolePrincipal(rb.RoleRef.Name, ResourceTypeNamespace.Id, rb.Namespace, useRoleAssignments),
				scopeType:    ResourceTypeNamespace.Id,
				scopeID:      rb.Namespace,
				controlPlane: isControlPlaneRole(rb.RoleRef.Name),
			})
		case RBACKindRole:
			// A RoleBinding's Role reference always resolves in the binding's own
			// namespace; there is no way to bind a Role from elsewhere.
			rules, ok := roleRules[namespacedName{namespace: rb.Namespace, name: rb.RoleRef.Name}]
			if !ok {
				l.Debug("skipping binding with unresolvable roleRef",
					zap.String("binding", rb.Name),
					zap.String("namespace", rb.Namespace),
					zap.String("role", rb.RoleRef.Name))
				continue
			}
			b.addRules(rules, ruleSource{
				principal: principalRef{
					resourceType: ResourceTypeRole.Id,
					resourceID:   rb.Namespace + "/" + rb.RoleRef.Name,
					expandVia:    roleMemberEntitlement,
				},
				scopeType:    ResourceTypeNamespace.Id,
				scopeID:      rb.Namespace,
				controlPlane: isControlPlaneRole(rb.RoleRef.Name),
			})
		}
	}

	index := b.finish()
	l.Debug("permission index built",
		zap.Int("classes", len(index.sorted)),
		zap.Int("named_objects", len(index.named)),
		zap.Int("object_scopes", len(index.objects)),
		zap.Int("inert_rules", index.inertRules))
	return index, nil
}

// clusterRolePrincipal picks the resource a cluster role's permission grants
// hang off at one scope.
//
// It has to be whichever resource carries a membership entitlement for that
// exact scope, because that entitlement is the expansion source and the SDK
// requires it to live on the principal. Under the sparse model that is the
// (role, scope) assignment; under the flat model it is the cluster role itself,
// whose entitlements are already per-namespace.
func clusterRolePrincipal(name, scopeType, scopeID string, useRoleAssignments bool) principalRef {
	if useRoleAssignments {
		key := assignmentKey{scopeType: scopeType, scopeID: scopeID, role: name}
		if scopeType == ResourceTypeCluster.Id {
			// role_assignment anchors cluster-wide pairs on the cluster
			// singleton's own object ID, not on the class ID's "*".
			key.scopeID = clusterResourceID
		}
		return principalRef{
			resourceType: ResourceTypeRoleAssignment.Id,
			resourceID:   roleAssignmentObjectID(key),
			expandVia:    assignedEntitlement,
		}
	}
	if scopeType == ResourceTypeCluster.Id {
		return principalRef{
			resourceType: ResourceTypeClusterRole.Id,
			resourceID:   name,
			expandVia:    clusterScopedMember,
		}
	}
	return principalRef{
		resourceType: ResourceTypeClusterRole.Id,
		resourceID:   name,
		expandVia:    fmt.Sprintf("%s:%s", scopeID, roleMemberEntitlement),
	}
}

// permissionIndexBuilder accumulates edges while walking the bindings.
type permissionIndexBuilder struct {
	// apiResources is what discovery knows. A missing entry means discovery did
	// not describe that resource, which is treated as unknown.
	apiResources map[schema.GroupResource]apiResourceInfo
	classes      map[permissionClass]map[string]map[principalRef]struct{}
	named        map[namedObject]map[string]map[principalRef]struct{}
	objects      map[objectScope]map[string]map[principalRef]struct{}
	// includeControlPlane keeps system: roles in the object layer.
	includeControlPlane bool
	inertRules          int
}

func (b *permissionIndexBuilder) addRules(rules []rbacv1.PolicyRule, src ruleSource) {
	for _, rule := range rules {
		b.addRule(rule, src)
	}
}

func (b *permissionIndexBuilder) addRule(rule rbacv1.PolicyRule, src ruleSource) {
	for _, url := range rule.NonResourceURLs {
		if src.scopeType != ResourceTypeCluster.Id {
			// Non-resource URLs are not namespaced, so a RoleBinding cannot
			// confer them at all.
			b.inertRules++
			continue
		}
		b.addClass(permissionClass{
			group:     nonResourceGroup,
			resource:  url,
			scopeType: src.scopeType,
			scopeID:   src.scopeID,
		}, rule.Verbs, src.principal)
	}

	for _, group := range rule.APIGroups {
		for _, resource := range rule.Resources {
			kind := resource
			if slash := strings.Index(resource, "/"); slash >= 0 {
				kind = resource[:slash]
			}
			if src.scopeType == ResourceTypeNamespace.Id && b.isClusterScoped(group, kind) {
				// Access conferred inside one namespace can never reach a
				// cluster-scoped kind, so the API server never matches this
				// rule. Emitting it would assert access the cluster does not
				// grant.
				b.inertRules++
				continue
			}
			class := permissionClass{
				group:     group,
				resource:  resource,
				scopeType: src.scopeType,
				scopeID:   src.scopeID,
			}
			if len(rule.ResourceNames) == 0 {
				b.addClass(class, rule.Verbs, src.principal)
				// The same rule reaches every object of every type the connector
				// models under it, so it also lands on those objects when the
				// tenant syncs them.
				b.addObjectPermissions(group, resource, rule.Verbs, src)
				continue
			}
			// A name-restricted rule confers nothing on the resource as a whole,
			// so it gets one narrowed target per name instead. Folding it into the
			// unrestricted target would claim, of a role that can read one Secret,
			// that it can read every Secret in the namespace.
			//
			// Only verbs that address an object come along: a request that carries
			// no object name never matches a rule with resourceNames. That is the
			// classic RBAC trap of trying to restrict list by name, and such a verb
			// authorizes nothing at all here.
			gated := make([]string, 0, len(rule.Verbs))
			for _, verb := range rule.Verbs {
				if addressesObject(verb, resource) {
					gated = append(gated, verb)
					continue
				}
				b.inertRules++
			}
			if len(gated) == 0 {
				continue
			}
			for _, name := range rule.ResourceNames {
				narrowed := class
				narrowed.name = name
				b.addClass(narrowed, gated, src.principal)
			}
			b.addNamedObjects(rule, resource, kind, gated, src)
		}
	}
}

// hasSubresource reports whether a kind actually has the named subresource, so a
// wildcard rule over one is not spread onto kinds without it.
//
// Discovery lists subresources as API resources of their own — deployments/scale,
// pods/exec — which is what makes this answerable. An undiscovered pair is
// allowed through for the same reason as an undiscovered kind: a CRD whose group
// failed discovery should not silently lose its permissions.
func (b *permissionIndexBuilder) hasSubresource(kind instanceKind, subresource string) bool {
	if subresource == "" {
		return true
	}
	if len(b.apiResources) == 0 {
		return true
	}
	_, known := b.apiResources[schema.GroupResource{
		Group:    kind.group,
		Resource: kind.plural + "/" + subresource,
	}]
	return known
}

// isClusterScoped reports whether an API resource is known not to be namespaced.
// A wildcard covers namespaced kinds too, and an undiscovered kind — a CRD whose
// group failed discovery — is left alone rather than dropped.
func (b *permissionIndexBuilder) isClusterScoped(group, kind string) bool {
	if group == verbAll || kind == verbAll {
		return false
	}
	info, known := b.apiResources[schema.GroupResource{Group: group, Resource: kind}]
	return known && !info.namespaced
}

func (b *permissionIndexBuilder) addClass(class permissionClass, verbs []string, principal principalRef) {
	byVerb, ok := b.classes[class]
	if !ok {
		byVerb = map[string]map[principalRef]struct{}{}
		b.classes[class] = byVerb
	}
	for _, verb := range verbs {
		principals, ok := byVerb[verb]
		if !ok {
			principals = map[principalRef]struct{}{}
			byVerb[verb] = principals
		}
		principals[principal] = struct{}{}
	}
}

// addNamedObjects records the edges a resourceNames rule puts on the real
// objects it names.
func (b *permissionIndexBuilder) addNamedObjects(
	rule rbacv1.PolicyRule,
	resource, kind string,
	verbs []string,
	src ruleSource,
) {
	resourceType, ok := instanceResourceTypes[kind]
	if !ok {
		// No resource type models this kind's objects, so there is no object to
		// point at. The narrowed target still records the permission.
		return
	}
	for _, verb := range verbs {
		slug := objectEntitlementSlug(resource, verb)
		for _, name := range rule.ResourceNames {
			objectID, ok := instanceObjectID(resourceType, src.scopeType, src.scopeID, name)
			if !ok {
				continue
			}
			// Not filtered by control-plane origin, unlike the wholesale
			// permissions below: a rule naming one object is precise and there is
			// one of it, so it carries none of the volume that filter exists for.
			b.addNamed(namedObject{resourceType: resourceType.Id, objectID: objectID}, slug, src.principal)
		}
	}
}

// addNamed records one object-specific permission.
func (b *permissionIndexBuilder) addNamed(object namedObject, slug string, principal principalRef) {
	bySlug, ok := b.named[object]
	if !ok {
		bySlug = map[string]map[principalRef]struct{}{}
		b.named[object] = bySlug
	}
	principals, ok := bySlug[slug]
	if !ok {
		principals = map[principalRef]struct{}{}
		bySlug[slug] = principals
	}
	principals[principal] = struct{}{}
}

// addObjectPermissions records what an unrestricted rule confers on every object
// of every modelled type it reaches, within one scope.
//
// Only the object-addressable half of the rule: "list pods" is a permission over
// the collection, so it belongs on the class target and not on any individual
// pod. The class target carries the whole rule either way.
//
// A wildcard resource is matched but not walked into subresources — "*" covers
// pods/exec as well as pods, and only the base verb is recorded here. That
// understates rather than overstates, and the "*" class target holds the full
// truth.
func (b *permissionIndexBuilder) addObjectPermissions(
	group, resource string,
	verbs []string,
	src ruleSource,
) {
	if src.controlPlane && !b.includeControlPlane {
		// The control plane's controllers hold cluster-wide rules, so every one of
		// them would land on every object of every type — 78% of this layer on a
		// stock cluster, none of it reviewable access. What they permit is still
		// reported on the api_resource targets, at one edge per API resource
		// rather than one per object.
		return
	}
	subresource := ""
	if slash := strings.Index(resource, "/"); slash >= 0 {
		subresource = resource[slash+1:]
	}
	for _, kind := range instanceKinds {
		if !kind.matches(group, resource) {
			continue
		}
		if !b.hasSubresource(kind, subresource) {
			// A wildcard rule over "*/scale" matches every resource that has a
			// scale subresource — which Secrets do not. Landing "get scale" on a
			// Secret would report a permission the API server can never evaluate.
			continue
		}
		if src.scopeType == ResourceTypeNamespace.Id && clusterScopedInstanceTypes[kind.resource.Id] {
			// Already counted inert above for a concrete rule; a wildcard rule
			// legitimately reaches namespaced kinds only.
			continue
		}
		scope := objectScope{resourceType: kind.resource.Id, scopeType: src.scopeType, scopeID: src.scopeID}
		for _, verb := range verbs {
			if !addressesObject(verb, resource) {
				continue
			}
			bySlug, ok := b.objects[scope]
			if !ok {
				bySlug = map[string]map[principalRef]struct{}{}
				b.objects[scope] = bySlug
			}
			slug := objectEntitlementSlug(resource, verb)
			principals, ok := bySlug[slug]
			if !ok {
				principals = map[principalRef]struct{}{}
				bySlug[slug] = principals
			}
			principals[src.principal] = struct{}{}
		}
	}
}

// instanceObjectID builds the object ID a resourceNames rule points at,
// reporting false when the rule identifies no single object.
func instanceObjectID(resourceType *v2.ResourceType, scopeType, scopeID, name string) (string, bool) {
	if clusterScopedInstanceTypes[resourceType.Id] {
		return name, true
	}
	if scopeType != ResourceTypeNamespace.Id {
		// A namespaced kind named by a cluster-wide binding means that name in
		// every namespace, including ones that do not exist yet, so no one
		// object is the target.
		return "", false
	}
	return scopeID + "/" + name, true
}

func (b *permissionIndexBuilder) finish() *PermissionIndex {
	index := &PermissionIndex{
		classes:    make(map[permissionClass]map[string][]principalRef, len(b.classes)),
		byID:       make(map[string]permissionClass, len(b.classes)),
		sorted:     make([]permissionClass, 0, len(b.classes)),
		named:      make(map[namedObject]map[string][]principalRef, len(b.named)),
		objects:    make(map[objectScope]map[string][]principalRef, len(b.objects)),
		inertRules: b.inertRules,
	}
	for class, byVerb := range b.classes {
		index.classes[class] = sortedPrincipals(byVerb)
		index.byID[class.objectID()] = class
		index.sorted = append(index.sorted, class)
	}
	// Sorted so paging is stable across calls; map order is not.
	sort.Slice(index.sorted, func(i, j int) bool { return index.sorted[i].less(index.sorted[j]) })

	for object, byVerb := range b.named {
		index.named[object] = sortedPrincipals(byVerb)
	}
	for scope, bySlug := range b.objects {
		index.objects[scope] = sortedPrincipals(bySlug)
	}
	return index
}

// sortedPrincipals flattens the dedup sets into stable slices, so two syncs of
// an unchanged cluster produce identical grants.
func sortedPrincipals(byVerb map[string]map[principalRef]struct{}) map[string][]principalRef {
	out := make(map[string][]principalRef, len(byVerb))
	for verb, set := range byVerb {
		principals := make([]principalRef, 0, len(set))
		for principal := range set {
			principals = append(principals, principal)
		}
		sort.Slice(principals, func(i, j int) bool { return principals[i].less(principals[j]) })
		out[verb] = principals
	}
	return out
}

// namespacedName identifies a namespaced Role.
type namespacedName struct {
	namespace string
	name      string
}

func listClusterRoleRules(ctx context.Context, client kubernetes.Interface) (map[string][]rbacv1.PolicyRule, error) {
	rules := make(map[string][]rbacv1.PolicyRule)
	continueToken := ""
	for {
		resp, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list cluster roles: %w", err)
		}
		for _, clusterRole := range resp.Items {
			rules[clusterRole.Name] = clusterRole.Rules
		}
		if resp.Continue == "" {
			return rules, nil
		}
		continueToken = resp.Continue
	}
}

func listRoleRules(ctx context.Context, client kubernetes.Interface) (map[namespacedName][]rbacv1.PolicyRule, error) {
	rules := make(map[namespacedName][]rbacv1.PolicyRule)
	continueToken := ""
	for {
		resp, err := client.RbacV1().Roles("").List(ctx, metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list roles: %w", err)
		}
		for _, role := range resp.Items {
			rules[namespacedName{namespace: role.Namespace, name: role.Name}] = role.Rules
		}
		if resp.Continue == "" {
			return rules, nil
		}
		continueToken = resp.Continue
	}
}

// apiResourceInfo is what discovery tells us about one API resource.
type apiResourceInfo struct {
	namespaced bool
	// verbs is what the API server will accept for this resource. Note that it
	// is not the same set as the RBAC verbs: impersonate, bind and escalate are
	// authorization-only and never appear here.
	verbs map[string]bool
}

// discoverAPIResources describes every API resource the cluster serves,
// subresources included — discovery lists pods/exec and deployments/scale as
// resources of their own, which is what makes the declared entitlement set and
// the wildcard-subresource check derivable rather than hand-maintained.
//
// It needs no extra access: the discovery endpoints are bound to
// system:authenticated through the system:discovery cluster role on every
// cluster.
//
// Partial failures are normal — an unavailable aggregated API server fails only
// its own group — so whatever was discovered is used and the rest stays unknown,
// which mints rather than drops.
func discoverAPIResources(ctx context.Context, client kubernetes.Interface) (map[schema.GroupResource]apiResourceInfo, error) {
	l := ctxzap.Extract(ctx)

	_, lists, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		if !discovery.IsGroupDiscoveryFailedError(err) {
			return nil, fmt.Errorf("failed to discover API resources: %w", err)
		}
		l.Debug("partial API discovery failure; undiscovered kinds are treated as unknown", zap.Error(err))
	}

	resources := make(map[schema.GroupResource]apiResourceInfo)
	for _, list := range lists {
		if list == nil {
			continue
		}
		groupVersion, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			l.Debug("skipping API resource list with unparseable group version",
				zap.String("group_version", list.GroupVersion))
			continue
		}
		for _, apiResource := range list.APIResources {
			verbs := make(map[string]bool, len(apiResource.Verbs))
			for _, verb := range apiResource.Verbs {
				verbs[verb] = true
			}
			key := schema.GroupResource{Group: groupVersion.Group, Resource: apiResource.Name}
			// Several versions of a group can serve the same resource; the verb
			// sets agree, so first writer wins and later ones only add.
			if existing, ok := resources[key]; ok {
				for verb := range verbs {
					existing.verbs[verb] = true
				}
				continue
			}
			resources[key] = apiResourceInfo{namespaced: apiResource.Namespaced, verbs: verbs}
		}
	}
	return resources, nil
}
