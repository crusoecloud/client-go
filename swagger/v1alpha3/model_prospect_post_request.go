/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha3
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type ProspectPostRequest struct {
	Company string `json:"company"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Source  string `json:"source"`
	UseCase string `json:"use_case"`
}
