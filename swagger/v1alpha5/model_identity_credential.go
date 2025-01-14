/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

import (
	"time"
)

type IdentityCredential struct {
	CreatedAt time.Time `json:"created_at"`
	Type_     string    `json:"type"`
	UpdatedAt time.Time `json:"updated_at"`
}