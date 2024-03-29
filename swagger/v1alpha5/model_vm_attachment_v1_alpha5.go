/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type VmAttachmentV1Alpha5 struct {
	AttachmentType string `json:"attachment_type"`
	Mode           string `json:"mode,omitempty"`
	VmId           string `json:"vm_id"`
}
