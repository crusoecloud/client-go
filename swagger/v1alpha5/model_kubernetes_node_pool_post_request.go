/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type KubernetesNodePoolPostRequest struct {
	// The number of nodes to be created.
	Count int64 `json:"count"`
	// The ID of the Infiniband partition to create node pool in. Must be in the location of the cluster if specified.
	IbPartitionId string `json:"ib_partition_id,omitempty"`
	// Name of the Kubernetes node pool.
	Name string `json:"name"`
	// Labels assigned to the node pool
	NodeLabels map[string]string `json:"node_labels,omitempty"`
	// Product name of the VM type to be created within this node pool.
	ProductName string `json:"product_name"`
	// SSH public key to use for all VMs created from this node pool.
	SshPublicKey string `json:"ssh_public_key,omitempty"`
	// The ID of the subnet to create the node pool in. Must be in the location of the cluster if specified. If not provided, the default subnet for the location will be used, if there is one.
	SubnetId string `json:"subnet_id,omitempty"`
}
