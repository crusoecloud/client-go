/*
 * rest-gateway
 *
 * Documentation of our REST API gateway that powers the user-facing website and CLI.
 *
 * API version: v1alpha1
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type Role struct {
	Id             string `json:"id,omitempty"`
	Name           string `json:"name,omitempty"`
	OrganizationId string `json:"organization_id,omitempty"`
	Relation       string `json:"relation,omitempty"`
}
