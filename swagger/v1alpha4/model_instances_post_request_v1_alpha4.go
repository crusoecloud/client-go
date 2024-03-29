/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha4
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// InstancesPostRequestV1Alpha4 is the request type for POST requests to the vms.instances endpoint.
type InstancesPostRequestV1Alpha4 struct {
	CommitmentPeriod  int64              `json:"commitment_period,omitempty"`
	Disks             []string           `json:"disks,omitempty"`
	IbPartitionId     string             `json:"ib_partition_id,omitempty"`
	Image             string             `json:"image,omitempty"`
	ImageChecksum     string             `json:"image_checksum,omitempty"`
	ImageId           string             `json:"image_id,omitempty"`
	Location          string             `json:"location,omitempty"`
	Name              string             `json:"name"`
	NetworkInterfaces []NetworkInterface `json:"network_interfaces,omitempty"`
	ProductName       string             `json:"product_name"`
	RoleId            string             `json:"role_id"`
	ShutdownScript    string             `json:"shutdown_script,omitempty"`
	SshPublicKey      string             `json:"ssh_public_key"`
	StartupScript     string             `json:"startup_script,omitempty"`
	Subnet            string             `json:"subnet,omitempty"`
}
