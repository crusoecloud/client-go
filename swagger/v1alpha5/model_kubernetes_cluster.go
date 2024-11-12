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
	// Configuration setting of the Kubernetes cluster.
	Configuration string `json:"configuration"`
	// DNS name of the cluster
	DnsName string `json:"dns_name"`
	// ID of the Kubernetes cluster.
	Id string `json:"id"`
	// Location of the Kubernetes cluster.
	Location string `json:"location"`
	// Name of the Kubernetes cluster.
	Name string `json:"name"`
	// List of IDs of node pools within the Kubernetes cluster.
	NodePools []string `json:"node_pools"`
	// IP Range for pods scheduled on K8s worker nodes
	PodCidr string `json:"pod_cidr,omitempty"`
	// Mask to be applied to PodCIDR
	PodCidrMask int32 `json:"pod_cidr_mask,omitempty"`
	// The ID of the project this Kubernetes cluster belongs to.
	ProjectId string `json:"project_id"`
	// IP Range for K8s services
	ServiceCidr string `json:"service_cidr,omitempty"`
	// State of the cluster
	State string `json:"state"`
	// The ID of the subnet this Kubernetes cluster belongs to.
	SubnetId string `json:"subnet_id"`
	// Version of the crusoe Kubernetes image of the Kubernetes cluster.
	Version string `json:"version"`
}
