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

type Manifest struct {
	Digest    string    `json:"digest,omitempty"`
	PushedAt  time.Time `json:"pushed_at,omitempty"`
	SizeBytes string    `json:"size_bytes,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
}
