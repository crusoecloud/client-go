/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type AuthCheckProvider struct {
	Id        string `json:"id"`
	IssuerUri string `json:"issuer_uri"`
	OrgName   string `json:"org_name"`
}
