/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type VersionDetails struct {
	BuildVersion      string `json:"BuildVersion,omitempty"`
	MajorMinorVersion string `json:"MajorMinorVersion,omitempty"`
	PatchVersion      string `json:"PatchVersion,omitempty"`
}
