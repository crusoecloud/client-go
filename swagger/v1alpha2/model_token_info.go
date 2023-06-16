/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha2
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// These are the fields returned from a GET request.
type TokenInfo struct {
	AccessKey string `json:"access_key"`
	Alias     string `json:"alias"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	LastUsed  string `json:"last_used"`
}
