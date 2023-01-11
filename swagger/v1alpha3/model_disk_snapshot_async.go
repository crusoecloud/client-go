/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha3
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

// DiskSnapshot contains identifying information about a disk snapshot and the recent operations that have been performed on it.
type DiskSnapshotAsync struct {
	CreatedAt   string      `json:"created_at,omitempty"`
	CreatedFrom string      `json:"created_from,omitempty"`
	Id          string      `json:"id,omitempty"`
	Operations  []Operation `json:"operations,omitempty"`
	Size        string      `json:"size,omitempty"`
}
