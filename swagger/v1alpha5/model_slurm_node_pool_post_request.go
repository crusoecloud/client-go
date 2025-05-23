/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type SlurmNodePoolPostRequest struct {
	// Cluster ID of the cluster this node pool belongs to.
	ClusterId string `json:"cluster_id"`
	// The desired number of nodes to be created.
	DesiredCount int64 `json:"desired_count"`
	// The ID of the Infiniband partition to create node pool in. Must be in the location of the cluster if specified.
	IbPartitionId string `json:"ib_partition_id,omitempty"`
	// Name of the slurm node pool.
	Name string `json:"name"`
	// Name of the slurm partition.
	PartitionName string `json:"partition_name"`
	// Product name of the VM type to be created within this node pool.
	Type_ string `json:"type"`
}
