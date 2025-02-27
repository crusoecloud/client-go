/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type SlurmNodePool struct {
	// The ID of the slurm cluster this node pool belongs to.
	ClusterId string `json:"cluster_id"`
	// Desired number of nodes within the node pool.
	DesiredCount int64 `json:"desired_count"`
	// IB Partition ID of the node pool.
	IbPartitionId string `json:"ib_partition_id"`
	// ID of the node pool.
	Id string `json:"id"`
	// Image ID for the slurm node pool.
	ImageId string `json:"image_id"`
	// List of IDs of instances within the node pool.
	InstanceIds []string `json:"instance_ids"`
	// Name of the node pool.
	Name string `json:"name"`
	// Slurm partition name of the node pool.
	PartitionName string `json:"partition_name"`
	// The ID of the project this slurm node pool belongs to.
	ProjectId string `json:"project_id"`
	// Number of nodes within the node pool.
	RunningCount int64 `json:"running_count"`
	// VM type of the node pool
	Type_ string `json:"type"`
}
