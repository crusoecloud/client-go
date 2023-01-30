/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha3
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

type Disk struct {
	AttachedTo []VmAttachment `json:"attached_to,omitempty"`
	CreatedAt  string         `json:"created_at,omitempty"`
	Id         string         `json:"id,omitempty"`
	Location   string         `json:"location,omitempty"`
	Name       string         `json:"name,omitempty"`
	Size       string         `json:"size,omitempty"`
	Type_      string         `json:"type,omitempty"`
	UpdatedAt  string         `json:"updated_at,omitempty"`
}
