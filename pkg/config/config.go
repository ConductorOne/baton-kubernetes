//go:generate go run ./gen

package config

import "github.com/conductorone/baton-sdk/pkg/field"

// https://github.com/kubernetes/cli-runtime/blob/v0.32.3/pkg/genericclioptions/config_flags.go#L349
// https://github.com/kubernetes/cli-runtime/blob/v0.32.3/pkg/genericclioptions/config_flags.go#L46

const (
	// Partial resource sync flags — off by default.
	FlagSyncConfigMaps   = "sync-config-maps"
	FlagSyncSecrets      = "sync-secrets"
	FlagSyncPods         = "sync-pods"
	FlagSyncNodes        = "sync-nodes"
	FlagSyncDeployments  = "sync-deployments"
	FlagSyncStatefulSets = "sync-stateful-sets"
	FlagSyncDaemonSets   = "sync-daemon-sets"

	// From k8s.io/cli-runtime/pkg/genericclioptions/config_flags.go.
	FlagClusterName        = "cluster"
	FlagAuthInfoName       = "user"
	FlagContext            = "context"
	FlagNamespace          = "namespace"
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
	FlagUsername           = "username"
	FlagPassword           = "password"
	FlagTimeout            = "request-timeout"
	FlagCacheDir           = "cache-dir"
	FlagDisableCompression = "disable-compression"
	FlagKubeconfig         = "kubeconfig"
)

var (
	kubeconfigField = field.StringField(
		FlagKubeconfig,
		field.WithDescription("Path to the kubeconfig file to use for CLI requests."),
	)
	cacheDirField = field.StringField(
		FlagCacheDir,
		field.WithDescription("Default cache directory"),
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
	usernameField = field.StringField(
		FlagUsername,
		field.WithDescription("Username for basic authentication to the API server"),
		field.WithRequired(false),
	)
	passwordField = field.StringField(
		FlagPassword,
		field.WithDescription("Password for basic authentication to the API server"),
		field.WithRequired(false),
		field.WithIsSecret(true),
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
	namespaceField = field.StringField(
		FlagNamespace,
		field.WithDescription("If present, the namespace scope for this CLI request"),
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
	syncConfigMapsField = field.BoolField(
		FlagSyncConfigMaps,
		field.WithDescription("Sync ConfigMap resources (disabled by default)"),
		field.WithDefaultValue(false),
	)
	syncSecretsField = field.BoolField(
		FlagSyncSecrets,
		field.WithDescription("Sync Secret resources (disabled by default)"),
		field.WithDefaultValue(false),
	)
	syncPodsField = field.BoolField(
		FlagSyncPods,
		field.WithDescription("Sync Pod resources (disabled by default)"),
		field.WithDefaultValue(false),
	)
	syncNodesField = field.BoolField(
		FlagSyncNodes,
		field.WithDescription("Sync Node resources (disabled by default)"),
		field.WithDefaultValue(false),
	)
	syncDeploymentsField = field.BoolField(
		FlagSyncDeployments,
		field.WithDescription("Sync Deployment resources (disabled by default)"),
		field.WithDefaultValue(false),
	)
	syncStatefulSetsField = field.BoolField(
		FlagSyncStatefulSets,
		field.WithDescription("Sync StatefulSet resources (disabled by default)"),
		field.WithDefaultValue(false),
	)
	syncDaemonSetsField = field.BoolField(
		FlagSyncDaemonSets,
		field.WithDescription("Sync DaemonSet resources (disabled by default)"),
		field.WithDefaultValue(false),
	)
)

// ConfigurationFields lists all connector-specific schema fields.
var ConfigurationFields = []field.SchemaField{
	kubeconfigField,
	cacheDirField,
	certFileField,
	keyFileField,
	bearerTokenField,
	impersonateField,
	impersonateUIDField,
	impersonateGroupField,
	usernameField,
	passwordField,
	clusterNameField,
	authInfoNameField,
	namespaceField,
	contextField,
	apiServerField,
	tlsServerNameField,
	insecureField,
	caFileField,
	timeoutField,
	disableCompressionField,
	syncConfigMapsField,
	syncSecretsField,
	syncPodsField,
	syncNodesField,
	syncDeploymentsField,
	syncStatefulSetsField,
	syncDaemonSetsField,
}

// ConfigRelations lists mutual-exclusivity and required-together constraints.
var ConfigRelations = []field.SchemaFieldRelationship{
	// --- Mutually Exclusive Authentication Methods ---

	// Token vs. Basic Auth (Username/Password)
	field.FieldsMutuallyExclusive(bearerTokenField, usernameField),
	field.FieldsMutuallyExclusive(bearerTokenField, passwordField),

	// Token vs. Cert Auth (Cert/Key)
	field.FieldsMutuallyExclusive(bearerTokenField, certFileField),
	field.FieldsMutuallyExclusive(bearerTokenField, keyFileField),

	// Token vs. Impersonation
	field.FieldsMutuallyExclusive(bearerTokenField, impersonateField),

	// Basic Auth vs. Cert Auth
	field.FieldsMutuallyExclusive(usernameField, certFileField),
	field.FieldsMutuallyExclusive(usernameField, keyFileField),
	field.FieldsMutuallyExclusive(passwordField, certFileField),
	field.FieldsMutuallyExclusive(passwordField, keyFileField),

	// Basic Auth vs. Impersonation
	field.FieldsMutuallyExclusive(usernameField, impersonateField),
	field.FieldsMutuallyExclusive(passwordField, impersonateField),

	// Cert Auth vs. Impersonation
	field.FieldsMutuallyExclusive(certFileField, impersonateField),
	field.FieldsMutuallyExclusive(keyFileField, impersonateField),

	// --- Required Together ---

	// Username and Password must be provided together
	field.FieldsRequiredTogether(usernameField, passwordField),

	// Client Certificate and Key must be provided together
	field.FieldsRequiredTogether(certFileField, keyFileField),
}

// Configuration is the full connector schema passed to DefineConfiguration.
var Configuration = field.NewConfiguration(
	ConfigurationFields,
	field.WithConstraints(ConfigRelations...),
)
