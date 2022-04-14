/*
 * rest-gateway
 *
 * Documentation of our REST API gateway that powers the user-facing website and CLI.
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

type Member struct {
	Id       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Relation string `json:"relation,omitempty"`
}
