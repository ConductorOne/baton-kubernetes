package connector

import (
	"context"
	"fmt"
	"net/url"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// clusterResourceID is the singleton's stable object ID. It never varies: a
// connector instance talks to exactly one cluster, and the ID has to stay put
// across syncs or every role assignment's scope would repoint. In particular it
// is deliberately not derived from the API server host, which moves when a
// cluster is recreated or reached through a different address.
const clusterResourceID = "cluster"

// clusterBuilder syncs a single resource standing for the cluster itself.
//
// It exists purely as the scope anchor for cluster-wide role assignments.
// ClusterRoleBindings grant access across the whole cluster rather than in a
// namespace, and a ScopeBindingTrait needs a resource to point at — C1 drops
// the relationship when the scope resource was never synced.
type clusterBuilder struct {
	// name labels the resource. Empty falls back to the API server host.
	name string
	// host is the API server URL, the fallback label.
	host string
	// enabled reports whether the sparse model is on. The type is registered
	// either way so a tenant selecting it can never fail the sync's resource
	// type validation, but with the sparse model off there is nothing for this
	// resource to anchor, so emitting it would add a resource the flat model
	// never had.
	enabled bool
}

func (c *clusterBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return ResourceTypeCluster
}

// List returns the single cluster resource, or nothing when the sparse model is
// off.
func (c *clusterBuilder) List(_ context.Context, _ *v2.ResourceId, _ rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	if !c.enabled {
		return nil, nil, nil
	}

	displayName := clusterDisplayName(c.name, c.host)
	profile := map[string]interface{}{
		profileKeyName: displayName,
	}
	if c.host != "" {
		profile["server"] = c.host
	}

	resource, err := rs.NewResource(
		displayName,
		ResourceTypeCluster,
		clusterResourceID,
		rs.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cluster resource: %w", err)
	}
	return []*v2.Resource{resource}, nil, nil
}

// clusterDisplayName picks the most meaningful label available.
//
// A caller-supplied name wins: the standalone CLI takes it from the kubeconfig
// and the cloud connectors know their own cluster's name. The API server host is
// only a fallback, and a weak one — an in-cluster deployment sees the ClusterIP
// of the kubernetes service there, which is the same address on most clusters.
// When there is nothing better, a plain label beats an address that looks
// identifying but is not.
func clusterDisplayName(name, host string) string {
	if name != "" {
		return name
	}
	if host == "" {
		return "Cluster"
	}
	u, err := url.Parse(host)
	if err != nil || u.Host == "" {
		return host
	}
	return u.Host
}

// Entitlements returns none: the cluster is a scope, not something to hold.
func (c *clusterBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns none, for the same reason as Entitlements.
func (c *clusterBuilder) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// clusterScopeResourceID returns the scope resource ID that cluster-wide role
// assignments point at.
func clusterScopeResourceID() *v2.ResourceId {
	return &v2.ResourceId{ResourceType: ResourceTypeCluster.Id, Resource: clusterResourceID}
}

func newClusterBuilder(name, host string, enabled bool) *clusterBuilder {
	return &clusterBuilder{name: name, host: host, enabled: enabled}
}
