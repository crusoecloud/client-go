/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type KubernetesCluster struct {
	// List of add-ons associated with the cluster.
	AddOns []string `json:"add_ons"`
	// The range of IP Addresses allocated to pods scheduled on worker nodes
	ClusterCidr string `json:"cluster_cidr,omitempty"`
	// Configuration setting of the Kubernetes cluster.
	Configuration string `json:"configuration"`
	// The time when the cluster was created
	CreatedAt string `json:"created_at"`
	// DNS name of the cluster
	DnsName string `json:"dns_name"`
	// ID of the Kubernetes cluster.
	Id string `json:"id"`
	// Location of the Kubernetes cluster.
	Location string `json:"location"`
	// Name of the Kubernetes cluster.
	Name string `json:"name"`
	// The mask size for cluster cidr
	NodeCidrMaskSize int32 `json:"node_cidr_mask_size,omitempty"`
	// List of IDs of node pools within the Kubernetes cluster.
	NodePools []string `json:"node_pools"`
	// The ID of the project this Kubernetes cluster belongs to.
	ProjectId string `json:"project_id"`
	// The range of IP Addresses allocated to K8s services
	ServiceClusterIpRange string `json:"service_cluster_ip_range,omitempty"`
	// State of the cluster
	State string `json:"state"`
	// The ID of the subnet this Kubernetes cluster belongs to.
	SubnetId string `json:"subnet_id"`
	// The time when the cluster was last updated
	UpdatedAt string `json:"updated_at"`
	// Version of the crusoe Kubernetes image of the Kubernetes cluster.
	Version string `json:"version"`
}
