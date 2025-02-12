/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type ListKubernetesVersionsResponse struct {
	// The list of available Kubernetes cluster versions.
	KubernetesClusterVersions []KubernetesClustersVersionInfo `json:"kubernetes_cluster_versions"`
	// The list of available Kubernetes node pool versions.
	KubernetesNodePoolVersions []KubernetesNodePoolsVersionInfo `json:"kubernetes_node_pool_versions"`
}
