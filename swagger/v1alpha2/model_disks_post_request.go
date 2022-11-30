/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha2
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

type DisksPostRequest struct {
	Location   string `json:"location,omitempty"`
	Name       string `json:"name"`
	RoleId     string `json:"role_id"`
	Size       string `json:"size,omitempty"`
	SnapshotId string `json:"snapshot_id,omitempty"`
	Type_      string `json:"type"`
}
