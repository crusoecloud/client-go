/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type LoadBalancersPostRequest struct {
	Algorithm    string              `json:"algorithm"`
	Destinations []NetworkTarget     `json:"destinations"`
	HealthCheck  *HealthCheckOptions `json:"health_check,omitempty"`
	Location     string              `json:"location"`
	Name         string              `json:"name"`
	Protocols    []string            `json:"protocols"`
	Type_        string              `json:"type,omitempty"`
	VpcSubnetId  string              `json:"vpc_subnet_id"`
}
