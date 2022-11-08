/*
 * rest-gateway
 *
 * Documentation of our REST API gateway that powers the user-facing website and CLI.
 *
 * API version: v1alpha1
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

type Instance struct {
	CommitmentEnd    string `json:"commitment_end,omitempty"`
	CommitmentPeriod int64  `json:"commitment_period,omitempty"`
	CreatedAt        string `json:"created_at,omitempty"`
	Id               string `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	ProductName      string `json:"product_name,omitempty"`
	RoleId           string `json:"role_id,omitempty"`
	SshDestination   string `json:"ssh_destination,omitempty"`
	State            string `json:"state,omitempty"`
}
