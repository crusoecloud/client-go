/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type HealthCheckOptionsExternalLb struct {
	// Number of allowed failures before considering the backend unhealthy.
	FailureCount int64 `json:"failure_count"`
	// Interval between health checks (in seconds).
	Interval int64 `json:"interval"`
	// Number of successful checks required to consider the backend healthy.
	SuccessCount int64 `json:"success_count"`
	// Timeout for health check responses (in seconds).
	Timeout int64 `json:"timeout"`
}
