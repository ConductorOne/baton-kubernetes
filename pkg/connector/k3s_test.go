package connector

import (
	"context"
	"fmt"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// setupK3sEnvironment creates a k3s container and returns everything needed to interact with it
func setupK3sEnvironment(t *testing.T) (context.Context, *kubernetes.Clientset, *rest.Config) {
	ctx := context.Background()

	// Start a k3s container
	k3sContainer, err := k3s.RunContainer(ctx,
		testcontainers.WithImage("docker.io/rancher/k3s:v1.27.11-k3s1"),
	)
	require.NoError(t, err, "Failed to start k3s container")

	// Ensure container is terminated after the test
	t.Cleanup(func() {
		if err := k3sContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate k3s container: %v", err)
		}
	})

	// Get the kubeconfig from the container
	kubeConfigYaml, err := k3sContainer.GetKubeConfig(ctx)
	require.NoError(t, err, "Failed to get kubeconfig")

	// Convert the kubeconfig to a rest.Config
	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeConfigYaml)
	require.NoError(t, err, "Failed to create REST config")

	// Increase QPS and Burst for the test client to avoid client-side throttling
	restConfig.QPS = 1000
	restConfig.Burst = 2000

	// Create a kubernetes clientset
	clientset, err := kubernetes.NewForConfig(restConfig)
	require.NoError(t, err, "Failed to create clientset")

	// Wait briefly for the cluster to be fully ready
	time.Sleep(5 * time.Second)

	return ctx, clientset, restConfig
}

// collectResources runs all syncers and collects resources into a map for easier verification
func collectResources(ctx context.Context, t *testing.T, c *Kubernetes) map[string]*v2.Resource {
	resources := make(map[string]*v2.Resource)

	// Get all syncers
	syncers := c.ResourceSyncers(ctx)
	require.NotEmpty(t, syncers, "Expected at least one resource syncer")

	// Iterate through each syncer
	for _, syncer := range syncers {
		resourceType := syncer.ResourceType(ctx)
		t.Logf("Processing syncer for resource type: %s", resourceType.Id)

		// Handle pagination
		token := &pagination.Token{}
		for {
			// Get a page of resources
			resourceList, nextToken, _, err := syncer.List(ctx, nil, token)
			require.NoError(t, err, "Failed to list resources from syncer")

			// Add resources to our map
			for _, resource := range resourceList {
				key := resource.Id.ResourceType + ":" + resource.Id.Resource
				resources[key] = resource
			}

			// Break if no more pages
			if nextToken == "" {
				break
			}

			// Update token for next page
			token = &pagination.Token{Token: nextToken}
		}
	}

	return resources
}

// Helper to create a namespace
func createNamespace(ctx context.Context, t *testing.T, client *kubernetes.Clientset, name string) *corev1.Namespace {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	createdNs, err := client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", name)
	return createdNs
}

// Helper to create a service account
func createServiceAccount(ctx context.Context, t *testing.T, client *kubernetes.Clientset, namespace, name string) *corev1.ServiceAccount {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	createdSa, err := client.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create service account %s/%s", namespace, name)
	return createdSa
}

// Helper to create a secret
func createSecret(ctx context.Context, t *testing.T, client *kubernetes.Clientset, namespace, name string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("secretpassword"),
		},
	}
	createdSecret, err := client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create secret %s/%s", namespace, name)
	return createdSecret
}

// Helper to create a role with permissions to get a specific secret
func createSecretGetterRole(ctx context.Context, t *testing.T, client *kubernetes.Clientset, namespace, name, secretName string) *rbacv1.Role {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{secretName},
				Verbs:         []string{"get"},
			},
		},
	}
	createdRole, err := client.RbacV1().Roles(namespace).Create(ctx, role, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create role %s/%s", namespace, name)
	return createdRole
}

// Helper to create a role binding
func createRoleBinding(ctx context.Context, t *testing.T, client *kubernetes.Clientset, namespace, name, roleName, saName string) *rbacv1.RoleBinding {
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     roleName,
		},
	}
	createdRb, err := client.RbacV1().RoleBindings(namespace).Create(ctx, roleBinding, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create role binding %s/%s", namespace, name)
	return createdRb
}

// Helper to check permission using SubjectAccessReview
func checkPermission(ctx context.Context, t *testing.T, client *kubernetes.Clientset,
	user string, verb, resource, subresource, namespace, name string) bool {
	review := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			User: user,
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace:   namespace,
				Verb:        verb,
				Resource:    resource,
				Subresource: subresource,
				Name:        name,
			},
		},
	}

	result, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create SubjectAccessReview")
	return result.Status.Allowed
}

// Helper function to check if a principal can perform an action in the Baton graph
func canPrincipalPerformAction(principalType, principalID, verb, resourceType, resourceID string,
	resources map[string]*v2.Resource, grants map[string]*v2.Grant) bool {
	fmt.Printf("Checking if %s:%s can %s %s:%s\n", principalType, principalID, verb, resourceType, resourceID)

	// First, find all roles that have the principal as a member
	var memberOfRoles []string
	for _, grant := range grants {
		if grant.Principal.Id.ResourceType == "role" &&
			grant.Entitlement.Id == "member" &&
			grant.Entitlement.Resource.Id.ResourceType == principalType &&
			grant.Entitlement.Resource.Id.Resource == principalID {
			roleID := grant.Principal.Id.Resource
			memberOfRoles = append(memberOfRoles, roleID)
			fmt.Printf("Found role membership: %s is member of role %s\n", principalID, roleID)
		}
	}

	// Then check if any of those roles have the permission
	for _, roleID := range memberOfRoles {
		// Look for grants from the role to the target resource
		for _, grant := range grants {
			if grant.Principal.Id.ResourceType == "role" &&
				grant.Principal.Id.Resource == roleID &&
				grant.Entitlement.Id == fmt.Sprintf("%s:%s", resourceType, verb) &&
				grant.Entitlement.Resource.Id.ResourceType == resourceType &&
				grant.Entitlement.Resource.Id.Resource == resourceID {
				fmt.Printf("Found permission grant: role %s can %s %s:%s\n",
					roleID,
					verb,
					resourceType, resourceID)
				return true
			}
		}
	}

	// Print all grants for debugging
	fmt.Println("Listing all available grants:")
	for _, grant := range grants {
		fmt.Printf("Grant: %s:%s %s %s:%s\n",
			grant.Principal.Id.ResourceType, grant.Principal.Id.Resource,
			grant.Entitlement.Id,
			grant.Entitlement.Resource.Id.ResourceType, grant.Entitlement.Resource.Id.Resource)
	}

	return false
}

// Helper to collect grant information from the connector
func collectGrants(ctx context.Context, t *testing.T, c *Kubernetes, resources map[string]*v2.Resource) map[string]*v2.Grant {
	grants := make(map[string]*v2.Grant)

	// Get all syncers
	syncers := c.ResourceSyncers(ctx)
	require.NotEmpty(t, syncers, "Expected at least one resource syncer")

	// Create a map for quick syncer lookup by resource type ID
	syncerMap := make(map[string]connectorbuilder.ResourceSyncer)
	for _, syncer := range syncers {
		syncerMap[syncer.ResourceType(ctx).GetId()] = syncer
	}

	// Iterate through collected resources once
	for _, resource := range resources {
		if resource.Id == nil || resource.Id.ResourceType == "" {
			t.Logf("Skipping resource with nil or empty ID type: %v", resource.Id)
			continue
		}

		// Find the appropriate syncer for this resource type
		syncer, ok := syncerMap[resource.Id.ResourceType]
		if !ok {
			t.Logf("Warning: No syncer found for resource type %s", resource.Id.ResourceType)
			continue
		}

		// Collect grants using the correct syncer
		token := &pagination.Token{}
		for {
			grantList, nextToken, _, err := syncer.Grants(ctx, resource, token)
			if err != nil {
				// Log the error but continue instead of failing the test
				t.Logf("Warning: Failed to get grants from resource %s:%s: %v",
					resource.Id.ResourceType, resource.Id.Resource, err)
				break
			}

			for _, grant := range grantList {
				key := fmt.Sprintf("%s:%s:%s:%s:%s",
					grant.Entitlement.Resource.Id.ResourceType,
					grant.Entitlement.Resource.Id.Resource,
					grant.Entitlement.Id,
					grant.Principal.Id.ResourceType,
					grant.Principal.Id.Resource)
				grants[key] = grant
			}

			if nextToken == "" {
				break
			}

			token = &pagination.Token{Token: nextToken}
		}
	}

	return grants
}

// TestRoleBindingScenario1 implements Scenario 1: Namespaced Access (SA -> Role -> Secret)
func TestRoleBindingScenario1(t *testing.T) {
	// Set up k3s
	ctx, clientset, restConfig := setupK3sEnvironment(t)

	// Step 1: Create test resources in k3s
	nsName := "test-ns-a"
	saName := "test-sa-a"
	secretName := "test-secret-a"
	roleName := "secret-getter-role"
	roleBindingName := "sa-secret-binding"

	// Create the namespace
	createNamespace(ctx, t, clientset, nsName)

	// Create a service account in the namespace
	createServiceAccount(ctx, t, clientset, nsName, saName)

	// Create a secret in the namespace
	createSecret(ctx, t, clientset, nsName, secretName)

	// Create a role that can get the specific secret
	createSecretGetterRole(ctx, t, clientset, nsName, roleName, secretName)

	// Create a role binding that gives the SA access to the role
	createRoleBinding(ctx, t, clientset, nsName, roleBindingName, roleName, saName)

	// Verify k8s permissions using SubjectAccessReview
	saUser := fmt.Sprintf("system:serviceaccount:%s:%s", nsName, saName)

	// SA should be able to get the specific secret
	allowed := checkPermission(ctx, t, clientset, saUser, "get", "secrets", "", nsName, secretName)
	require.True(t, allowed, "Service account should be allowed to get the secret")

	// SA should NOT be able to list secrets
	allowed = checkPermission(ctx, t, clientset, saUser, "list", "secrets", "", nsName, "")
	require.False(t, allowed, "Service account should NOT be allowed to list secrets")

	// Step 2: Run Baton connector against this k3s cluster
	c, err := New(ctx, restConfig)
	require.NoError(t, err, "Failed to create connector")

	// Step 3: Collect resources and grants from the connector
	resources := collectResources(ctx, t, c)
	grants := collectGrants(ctx, t, c, resources)

	t.Logf("Collected %d resources and %d grants", len(resources), len(grants))

	// Step 4: Verify Baton graph using our helper function

	// Check that SA can get the specific secret
	canGet := canPrincipalPerformAction(
		"service_account", fmt.Sprintf("%s/%s", nsName, saName),
		"get",
		"secret", fmt.Sprintf("%s/%s", nsName, secretName),
		resources, grants,
	)
	require.True(t, canGet, "Baton graph should show SA can get the secret")

	// Check that SA cannot list secrets
	canList := canPrincipalPerformAction(
		"service_account", fmt.Sprintf("%s/%s", nsName, saName),
		"list",
		"secret", "*",
		resources, grants,
	)
	require.False(t, canList, "Baton graph should show SA cannot list secrets")

	t.Log("Successfully verified Scenario 1: Namespaced Access (SA -> Role -> Secret)")
}
