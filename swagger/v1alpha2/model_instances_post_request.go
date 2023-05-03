/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha2
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type InstancesPostRequest struct {
	CommitmentPeriod int64  `json:"commitment_period,omitempty"`
	ImageChecksum    string `json:"image_checksum,omitempty"`
	ImageId          string `json:"image_id,omitempty"`
	Name             string `json:"name"`
	ProductName      string `json:"product_name"`
	RoleId           string `json:"role_id"`
	ShutdownScript   string `json:"shutdown_script,omitempty"`
	SshPublicKey     string `json:"ssh_public_key"`
	StartupScript    string `json:"startup_script,omitempty"`
}
