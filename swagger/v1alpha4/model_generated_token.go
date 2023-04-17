/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha4
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// These are the fields returned from a PUT request.
type GeneratedToken struct {
	AccessKey string `json:"access_key,omitempty"`
	Alias     string `json:"alias,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
}
