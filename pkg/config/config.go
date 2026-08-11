//go:generate go run ./gen

package config

import "github.com/conductorone/baton-sdk/pkg/field"

// https://github.com/kubernetes/cli-runtime/blob/v0.32.3/pkg/genericclioptions/config_flags.go#L349
// https://github.com/kubernetes/cli-runtime/blob/v0.32.3/pkg/genericclioptions/config_flags.go#L46

const (
	// From k8s.io/cli-runtime/pkg/genericclioptions/config_flags.go.
	FlagClusterName        = "cluster"
	FlagAuthInfoName       = "user"
	FlagContext            = "context"
	FlagAPIServer          = "server"
	FlagTLSServerName      = "tls-server-name"
	FlagInsecure           = "insecure-skip-tls-verify"
	FlagCertFile           = "client-certificate"
	FlagKeyFile            = "client-key"
	FlagCAFile             = "certificate-authority"
	FlagBearerToken        = "token"
	FlagImpersonate        = "as"
	FlagImpersonateUID     = "as-uid"
	FlagImpersonateGroup   = "as-group"
	FlagTimeout            = "request-timeout"
	FlagDisableCompression = "disable-compression"
	FlagKubeconfig         = "kubeconfig"

	// FlagUseRoleAssignments is this connector's own flag, not one of
	// cli-runtime's.
	FlagUseRoleAssignments = "use-role-assignments"
)

var (
	kubeconfigField = field.StringField(
		FlagKubeconfig,
		field.WithDescription("Path to the kubeconfig file to use for CLI requests."),
	)
	certFileField = field.StringField(
		FlagCertFile,
		field.WithDescription("Path to a client certificate file for TLS"),
		field.WithRequired(false),
	)
	keyFileField = field.StringField(
		FlagKeyFile,
		field.WithDescription("Path to a client key file for TLS"),
		field.WithRequired(false),
	)
	bearerTokenField = field.StringField(
		FlagBearerToken,
		field.WithDescription("Bearer token for authentication to the API server"),
		field.WithRequired(false),
		field.WithIsSecret(true),
	)
	impersonateField = field.StringField(
		FlagImpersonate,
		field.WithDescription("Username to impersonate for the operation. User could be a regular user or a service account in a namespace."),
		field.WithRequired(false),
	)
	impersonateUIDField = field.StringField(
		FlagImpersonateUID,
		field.WithDescription("UID to impersonate for the operation."),
		field.WithRequired(false),
	)
	impersonateGroupField = field.StringSliceField(FlagImpersonateGroup,
		field.WithDescription("Group to impersonate for the operation, this flag can be repeated to specify multiple groups."),
		field.WithRequired(false),
	)
	clusterNameField = field.StringField(
		FlagClusterName,
		field.WithDescription("The name of the kubeconfig cluster to use"),
		field.WithRequired(false),
	)
	authInfoNameField = field.StringField(
		FlagAuthInfoName,
		field.WithDescription("The name of the kubeconfig user to use"),
		field.WithRequired(false),
	)
	contextField = field.StringField(
		FlagContext,
		field.WithDescription("The name of the kubeconfig context to use"),
		field.WithRequired(false),
	)
	apiServerField = field.StringField(
		FlagAPIServer,
		field.WithDescription("The address and port of the Kubernetes API server"),
		field.WithRequired(false),
	)
	tlsServerNameField = field.StringField(
		FlagTLSServerName,
		field.WithDescription("Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used"),
		field.WithRequired(false),
	)
	insecureField = field.BoolField(
		FlagInsecure,
		field.WithDescription("If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure"),
		field.WithDefaultValue(false),
	)
	caFileField = field.StringField(FlagCAFile,
		field.WithDescription("Path to a cert file for the certificate authority"),
		field.WithRequired(false),
	)
	timeoutField = field.StringField(FlagTimeout,
		field.WithDescription(
			"The length of time to wait before giving up on a single server request."+
				" Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h)."+
				" A value of zero means don't timeout requests."),
		field.WithDefaultValue("0"),
	)
	disableCompressionField = field.BoolField(
		FlagDisableCompression,
		field.WithDescription("If true, opt-out of response compression for all requests to the server"),
		field.WithDefaultValue(false),
	)
	// useRoleAssignmentsField switches cluster role access from the flat model
	// to the sparse one. The two are mutually exclusive by construction: with it
	// on, cluster_role stops emitting entitlements and grants and the same access
	// is expressed as role_assignment resources, so it is never counted twice.
	useRoleAssignmentsField = field.BoolField(
		FlagUseRoleAssignments,
		field.WithDisplayName("Sync cluster role assignments"),
		field.WithDescription(
			"If true, sync each (cluster role, scope) pair that has a binding as a role assignment resource,"+
				" instead of declaring one entitlement per cluster role per namespace."+
				" Namespaced roles are unaffected."),
		field.WithDefaultValue(false),
	)
)

// ConfigurationFields lists all connector-specific schema fields.
var ConfigurationFields = []field.SchemaField{
	kubeconfigField,
	certFileField,
	keyFileField,
	bearerTokenField,
	impersonateField,
	impersonateUIDField,
	impersonateGroupField,
	clusterNameField,
	authInfoNameField,
	contextField,
	apiServerField,
	tlsServerNameField,
	insecureField,
	caFileField,
	timeoutField,
	disableCompressionField,
	useRoleAssignmentsField,
}

// ConfigRelations lists mutual-exclusivity and required-together constraints.
var ConfigRelations = []field.SchemaFieldRelationship{
	// --- Mutually Exclusive Authentication Methods ---

	// Token vs. Cert Auth (Cert/Key)
	field.FieldsMutuallyExclusive(bearerTokenField, certFileField),
	field.FieldsMutuallyExclusive(bearerTokenField, keyFileField),

	// Token vs. Impersonation
	field.FieldsMutuallyExclusive(bearerTokenField, impersonateField),

	// Cert Auth vs. Impersonation
	field.FieldsMutuallyExclusive(certFileField, impersonateField),
	field.FieldsMutuallyExclusive(keyFileField, impersonateField),

	// --- Required Together ---

	// Client Certificate and Key must be provided together
	field.FieldsRequiredTogether(certFileField, keyFileField),
}

// Configuration is the full connector schema passed to DefineConfiguration.
var Configuration = field.NewConfiguration(
	ConfigurationFields,
	field.WithConstraints(ConfigRelations...),
)
