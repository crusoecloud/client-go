/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// These are the fields returned from a GET request.
type LimitedUsageApiKeyInfo struct {
	Alias     string `json:"alias"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	KeyId     string `json:"key_id"`
	LastUsed  string `json:"last_used"`
	Usage     string `json:"usage"`
}
