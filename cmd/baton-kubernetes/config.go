package main

import (
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/spf13/viper"

	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/utils/pointer"
)

// https://github.com/kubernetes/cli-runtime/blob/v0.32.3/pkg/genericclioptions/config_flags.go#L349
// https://github.com/kubernetes/cli-runtime/blob/v0.32.3/pkg/genericclioptions/config_flags.go#L46

const (
	// From k8s.io/cli-runtime/pkg/genericclioptions/config_flags.go
	flagClusterName        = "cluster"
	flagAuthInfoName       = "user"
	flagContext            = "context"
	flagNamespace          = "namespace"
	flagAPIServer          = "server"
	flagTLSServerName      = "tls-server-name"
	flagInsecure           = "insecure-skip-tls-verify"
	flagCertFile           = "client-certificate"
	flagKeyFile            = "client-key"
	flagCAFile             = "certificate-authority"
	flagBearerToken        = "token"
	flagImpersonate        = "as"
	flagImpersonateUID     = "as-uid"
	flagImpersonateGroup   = "as-group"
	flagUsername           = "username"
	flagPassword           = "password"
	flagTimeout            = "request-timeout"
	flagCacheDir           = "cache-dir"
	flagDisableCompression = "disable-compression"
	flagKubeconfig         = "kubeconfig"
)

var (
	kubeconfigField         = field.StringField(flagKubeconfig, field.WithDescription("Path to the kubeconfig file to use for CLI requests."))
	cacheDirField           = field.StringField(flagCacheDir, field.WithDescription("Default cache directory"))
	certFileField           = field.StringField(flagCertFile, field.WithDescription("Path to a client certificate file for TLS"), field.WithRequired(false))
	keyFileField            = field.StringField(flagKeyFile, field.WithDescription("Path to a client key file for TLS"), field.WithRequired(false))
	bearerTokenField        = field.StringField(flagBearerToken, field.WithDescription("Bearer token for authentication to the API server"), field.WithRequired(false))
	impersonateField        = field.StringField(flagImpersonate, field.WithDescription("Username to impersonate for the operation. User could be a regular user or a service account in a namespace."), field.WithRequired(false))
	impersonateUIDField     = field.StringField(flagImpersonateUID, field.WithDescription("UID to impersonate for the operation."), field.WithRequired(false))
	impersonateGroupField   = field.StringSliceField(flagImpersonateGroup, field.WithDescription("Group to impersonate for the operation, this flag can be repeated to specify multiple groups."), field.WithRequired(false))
	usernameField           = field.StringField(flagUsername, field.WithDescription("Username for basic authentication to the API server"), field.WithRequired(false))
	passwordField           = field.StringField(flagPassword, field.WithDescription("Password for basic authentication to the API server"), field.WithRequired(false), field.WithIsSecret(true))
	clusterNameField        = field.StringField(flagClusterName, field.WithDescription("The name of the kubeconfig cluster to use"), field.WithRequired(false))
	authInfoNameField       = field.StringField(flagAuthInfoName, field.WithDescription("The name of the kubeconfig user to use"), field.WithRequired(false))
	namespaceField          = field.StringField(flagNamespace, field.WithDescription("If present, the namespace scope for this CLI request"), field.WithRequired(false))
	contextField            = field.StringField(flagContext, field.WithDescription("The name of the kubeconfig context to use"), field.WithRequired(false))
	apiServerField          = field.StringField(flagAPIServer, field.WithDescription("The address and port of the Kubernetes API server"), field.WithRequired(false))
	tlsServerNameField      = field.StringField(flagTLSServerName, field.WithDescription("Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used"), field.WithRequired(false))
	insecureField           = field.BoolField(flagInsecure, field.WithDescription("If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure"), field.WithDefaultValue(false))
	caFileField             = field.StringField(flagCAFile, field.WithDescription("Path to a cert file for the certificate authority"), field.WithRequired(false))
	timeoutField            = field.StringField(flagTimeout, field.WithDescription("The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests."), field.WithDefaultValue("0"))
	disableCompressionField = field.BoolField(flagDisableCompression, field.WithDescription("If true, opt-out of response compression for all requests to the server"), field.WithDefaultValue(false))
)

func getConfigurationFields() []field.SchemaField {
	return []field.SchemaField{
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
	}
}

func getFieldRelationships() []field.SchemaFieldRelationship {
	return []field.SchemaFieldRelationship{
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
}

// GetConfig is run after the configuration is loaded, and should return an
// error if it isn't valid. Implementing this function is optional, it only
// needs to perform extra validations that cannot be encoded with configuration
// parameters.
func GetConfig(v *viper.Viper) (*clioptions.ConfigFlags, error) {
	opt := clioptions.NewConfigFlags(true)

	// We need to check if the flags were explicitly set by the user in viper,
	// rather than just using the default value from NewConfigFlags.
	// viper.IsSet() helps here.
	if v.IsSet(flagKubeconfig) {
		kubeconfigPath := v.GetString(flagKubeconfig)
		// Check if the kubeconfig file exists
		if kubeconfigPath != "" {
			_, err := os.Stat(kubeconfigPath)
			if err != nil {
				if os.IsNotExist(err) {
					return nil, fmt.Errorf("specified kubeconfig file does not exist: %s", kubeconfigPath)
				}
				return nil, fmt.Errorf("error accessing kubeconfig file: %w", err)
			}
		}
		opt.KubeConfig = pointer.String(kubeconfigPath)
	}

	if v.IsSet(flagCacheDir) {
		opt.CacheDir = pointer.String(v.GetString(flagCacheDir))
	}
	if v.IsSet(flagCertFile) {
		opt.CertFile = pointer.String(v.GetString(flagCertFile))
	}
	if v.IsSet(flagKeyFile) {
		opt.KeyFile = pointer.String(v.GetString(flagKeyFile))
	}
	if v.IsSet(flagBearerToken) {
		opt.BearerToken = pointer.String(v.GetString(flagBearerToken))
	}
	if v.IsSet(flagImpersonate) {
		opt.Impersonate = pointer.String(v.GetString(flagImpersonate))
	}
	if v.IsSet(flagImpersonateUID) {
		opt.ImpersonateUID = pointer.String(v.GetString(flagImpersonateUID))
	}
	if v.IsSet(flagImpersonateGroup) {
		// Need to get the string slice for ImpersonateGroup
		groups := v.GetStringSlice(flagImpersonateGroup)
		opt.ImpersonateGroup = &groups
	}
	if v.IsSet(flagUsername) {
		opt.Username = pointer.String(v.GetString(flagUsername))
	}
	if v.IsSet(flagPassword) {
		opt.Password = pointer.String(v.GetString(flagPassword))
	}
	if v.IsSet(flagClusterName) {
		opt.ClusterName = pointer.String(v.GetString(flagClusterName))
	}
	if v.IsSet(flagAuthInfoName) {
		opt.AuthInfoName = pointer.String(v.GetString(flagAuthInfoName))
	}
	if v.IsSet(flagNamespace) {
		opt.Namespace = pointer.String(v.GetString(flagNamespace))
	}
	if v.IsSet(flagContext) {
		opt.Context = pointer.String(v.GetString(flagContext))
	}
	if v.IsSet(flagAPIServer) {
		opt.APIServer = pointer.String(v.GetString(flagAPIServer))
	}
	if v.IsSet(flagTLSServerName) {
		opt.TLSServerName = pointer.String(v.GetString(flagTLSServerName))
	}
	if v.IsSet(flagInsecure) {
		opt.Insecure = pointer.Bool(v.GetBool(flagInsecure))
	}
	if v.IsSet(flagCAFile) {
		opt.CAFile = pointer.String(v.GetString(flagCAFile))
	}
	if v.IsSet(flagTimeout) {
		opt.Timeout = pointer.String(v.GetString(flagTimeout))
	}
	if v.IsSet(flagDisableCompression) {
		opt.DisableCompression = pointer.Bool(v.GetBool(flagDisableCompression))
	}

	return opt, nil
}
