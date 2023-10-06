/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha4
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// SingleInstanceGetResponseV1Alpha4 is the response type for GET requests to compute/vms/instances/{vm_id}.
type SingleInstanceGetResponseV1Alpha4 struct {
	Instance *InstanceV1Alpha4 `json:"instance"`
}