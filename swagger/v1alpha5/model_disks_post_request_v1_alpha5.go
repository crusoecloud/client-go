/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type DisksPostRequestV1Alpha5 struct {
	BlockSize  int64  `json:"block_size,omitempty"`
	Location   string `json:"location,omitempty"`
	Name       string `json:"name"`
	Size       string `json:"size,omitempty"`
	SnapshotId string `json:"snapshot_id,omitempty"`
	Type_      string `json:"type"`
}
