/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha2
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

// Identity contains the Traits Island stores for a User inside of Kratos. These are the fields returned from a GET or PUT request.
type Identity struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}