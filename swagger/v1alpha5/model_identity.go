/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// Identity contains the Traits Island stores for a User inside of Kratos. These are the fields returned from a GET or PUT request.
type Identity struct {
	AcceptedTos      bool   `json:"accepted_tos,omitempty"`
	CompanyName      string `json:"company_name,omitempty"`
	Email            string `json:"email"`
	Id               string `json:"id"`
	IsRecovery       bool   `json:"is_recovery,omitempty"`
	Name             string `json:"name"`
	RegistrationType string `json:"registration_type,omitempty"`
	Role             string `json:"role"`
	UserState        string `json:"user_state,omitempty"`
}
