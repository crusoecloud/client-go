/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// KubernetesAuthenticationClientCertificateDetails contains information to authenticate to a Kubernetes cluster with client certificates.
type KubernetesAuthenticationClientCertificateDetails struct {
	// Address of the Kubernetes cluster to authenticate to
	ClusterAddress string `json:"cluster_address"`
	// CA Certificate of the Kubernetes cluster to authenticate to
	ClusterCaCertificate string `json:"cluster_ca_certificate"`
	// Name of the Kubernetes cluster to authenticate to
	ClusterName string `json:"cluster_name"`
	// User's Client certificate for authenticating to the cluster.
	UserClientCertificate string `json:"user_client_certificate"`
	// The private key associated with the user's Client certificate.
	UserClientKey string `json:"user_client_key"`
	// Name of the authenticating user
	UserName string `json:"user_name"`
}
