/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type NetworkTarget struct {
	Cidr       string `json:"cidr,omitempty"`
	ResourceId string `json:"resource_id,omitempty"`
}
