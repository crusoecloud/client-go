/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha4
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

type VmAttachment struct {
	AttachmentType string `json:"attachment_type,omitempty"`
	VmId           string `json:"vm_id,omitempty"`
}
