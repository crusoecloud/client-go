/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type Backend struct {
	// IP address of the backend server.
	Ip string `json:"ip"`
	// Port on which the backend server listens.
	Port int64 `json:"port"`
	// Status of the backend server.
	Status string `json:"status"`
}