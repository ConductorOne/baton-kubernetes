package connector

import (
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
)

// Profile keys for RBAC rule data on role and cluster_role resources.
const (
	profileKeyRules               = "rules"
	profileKeyRuleCount           = "ruleCount"
	profileKeyVerbs               = "verbs"
	profileKeyResources           = "resources"
	profileKeyAPIGroups           = "apiGroups"
	profileKeyResourceNames       = "resourceNames"
	profileKeyNonResourceURLs     = "nonResourceURLs"
	profileKeyCanModify           = "canModify"
	profileKeyModifiableVerbs     = "modifiableVerbs"
	profileKeyModifiableVerbCount = "modifiableVerbCount"
	profileKeyAggregated          = "aggregated"
)

// Kubernetes RBAC verbs.
const (
	verbGet              = "get"
	verbList             = "list"
	verbWatch            = "watch"
	verbCreate           = "create"
	verbUpdate           = "update"
	verbPatch            = "patch"
	verbDelete           = "delete"
	verbDeleteCollection = "deletecollection"
	verbBind             = "bind"
	verbEscalate         = "escalate"
	verbImpersonate      = "impersonate"
	verbAll              = "*"
)

// modifiableVerbs are the verbs that change cluster state or escalate privileges.
// A role containing any of them is flagged canModify, which reviewers use as the
// risk signal when attesting access.
var modifiableVerbs = map[string]bool{
	verbCreate:           true,
	verbUpdate:           true,
	verbPatch:            true,
	verbDelete:           true,
	verbDeleteCollection: true,
	verbBind:             true,
	verbEscalate:         true,
	verbImpersonate:      true,
	verbAll:              true,
}

// PolicyRulesProfile converts a Role's or ClusterRole's rules into profile data:
// the structured rules themselves plus unions and a risk summary, so a reviewer
// can see what the role actually permits without leaving ConductorOne.
//
// For aggregated ClusterRoles the API server's aggregation controller writes the
// effective rules into the object, so no aggregation is performed here.
func PolicyRulesProfile(rules []rbacv1.PolicyRule) map[string]interface{} {
	structured := make([]interface{}, 0, len(rules))
	apiGroups := map[string]bool{}
	resources := map[string]bool{}
	verbs := map[string]bool{}
	resourceNames := map[string]bool{}
	nonResourceURLs := map[string]bool{}
	modifiable := map[string]bool{}

	for _, rule := range rules {
		entry := map[string]interface{}{}
		addRuleField(entry, profileKeyAPIGroups, rule.APIGroups, apiGroups)
		addRuleField(entry, profileKeyResources, rule.Resources, resources)
		addRuleField(entry, profileKeyResourceNames, rule.ResourceNames, resourceNames)
		addRuleField(entry, profileKeyNonResourceURLs, rule.NonResourceURLs, nonResourceURLs)
		addRuleField(entry, profileKeyVerbs, rule.Verbs, verbs)

		for _, verb := range rule.Verbs {
			if modifiableVerbs[verb] {
				modifiable[verb] = true
			}
		}
		structured = append(structured, entry)
	}

	profile := map[string]interface{}{
		profileKeyRules:               structured,
		profileKeyRuleCount:           len(rules),
		profileKeyVerbs:               sortedKeys(verbs),
		profileKeyResources:           sortedKeys(resources),
		profileKeyAPIGroups:           sortedKeys(apiGroups),
		profileKeyCanModify:           len(modifiable) > 0,
		profileKeyModifiableVerbs:     sortedKeys(modifiable),
		profileKeyModifiableVerbCount: len(modifiable),
	}
	// Only present when the role actually narrows to named objects or non-resource URLs.
	if len(resourceNames) > 0 {
		profile[profileKeyResourceNames] = sortedKeys(resourceNames)
	}
	if len(nonResourceURLs) > 0 {
		profile[profileKeyNonResourceURLs] = sortedKeys(nonResourceURLs)
	}
	return profile
}

// addRuleField copies a rule's string slice into the per-rule entry (when
// non-empty) and accumulates its values into the role-wide union.
func addRuleField(entry map[string]interface{}, key string, values []string, union map[string]bool) {
	if len(values) == 0 {
		return
	}
	entry[key] = toAnySlice(values)
	for _, v := range values {
		union[v] = true
	}
}

// toAnySlice converts a string slice for structpb serialization, which does not
// accept []string.
func toAnySlice(values []string) []interface{} {
	out := make([]interface{}, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	return out
}

// sortedKeys returns the set's keys in a stable order so profiles do not churn
// between syncs.
func sortedKeys(set map[string]bool) []interface{} {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return toAnySlice(keys)
}
