/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha4
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type Disk struct {
	AttachedTo   []VmAttachment `json:"attached_to"`
	CreatedAt    string         `json:"created_at"`
	Id           string         `json:"id"`
	Location     string         `json:"location,omitempty"`
	Name         string         `json:"name"`
	SerialNumber string         `json:"serial_number"`
	Size         string         `json:"size"`
	Type_        string         `json:"type"`
	UpdatedAt    string         `json:"updated_at"`
}
