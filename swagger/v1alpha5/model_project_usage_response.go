/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type ProjectUsageResponse struct {
	BillableMetric string  `json:"billable_metric"`
	Date           string  `json:"date"`
	ProjectId      string  `json:"project_id"`
	Quantity       float64 `json:"quantity"`
	Region         string  `json:"region"`
	ReservationId  string  `json:"reservation_id"`
	ResourceType   string  `json:"resource_type"`
}
