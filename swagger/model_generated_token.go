/*
 * rest-gateway
 *
 * Documentation of our REST API gateway that powers the user-facing website and CLI.
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

// These are the fields returned from a PUT request.
type GeneratedToken struct {
	AccessKey string `json:"access_key,omitempty"`
	Alias string `json:"alias,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
}
