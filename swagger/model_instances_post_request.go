/*
 * rest-gateway
 *
 * Documentation of our REST API gateway that powers the user-facing website and CLI.
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

type InstancesPostRequest struct {
	ImageChecksum string `json:"image_checksum,omitempty"`
	ImageId string `json:"image_id,omitempty"`
	Name string `json:"name,omitempty"`
	ProductName string `json:"product_name,omitempty"`
	RoleId string `json:"role_id,omitempty"`
	SshPublicKey string `json:"ssh_public_key,omitempty"`
	Type_ *VmType `json:"type,omitempty"`
}