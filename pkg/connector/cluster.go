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
// across syncs or every role assignment's scope would repoint.
const clusterResourceID = "cluster"

// clusterBuilder syncs a single resource standing for the cluster itself.
//
// It exists purely as the scope anchor for cluster-wide role assignments.
// ClusterRoleBindings grant access across the whole cluster rather than in a
// namespace, and a ScopeBindingTrait needs a resource to point at — C1 drops
// the relationship when the scope resource was never synced.
type clusterBuilder struct {
	// host is the API server URL, used only for the display name so the resource
	// is identifiable in a tenant with several clusters connected.
	host string
}

func (c *clusterBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return ResourceTypeCluster
}

// List returns the single cluster resource.
func (c *clusterBuilder) List(_ context.Context, _ *v2.ResourceId, _ rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	resource, err := rs.NewResource(
		clusterDisplayName(c.host),
		ResourceTypeCluster,
		clusterResourceID,
		rs.WithResourceProfile(map[string]interface{}{
			profileKeyName: clusterDisplayName(c.host),
			"server":       c.host,
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cluster resource: %w", err)
	}
	return []*v2.Resource{resource}, nil, nil
}

// clusterDisplayName prefers the API server host, which is what distinguishes
// one cluster from another to an operator. It falls back to a bare label when
// the server URL is unusable, since a display name is cosmetic and must never
// fail the sync.
func clusterDisplayName(host string) string {
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

// clusterResourceID returns the scope resource ID that cluster-wide role
// assignments point at.
func clusterScopeResourceID() *v2.ResourceId {
	return &v2.ResourceId{ResourceType: ResourceTypeCluster.Id, Resource: clusterResourceID}
}

func newClusterBuilder(host string) *clusterBuilder {
	return &clusterBuilder{host: host}
}
