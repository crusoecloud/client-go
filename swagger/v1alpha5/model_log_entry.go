/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type LogEntry struct {
	// Name of the action
	Action string `json:"action"`
	// Actor: who performed the action.
	Actor string `json:"actor"`
	// ActorEmail: the email address of the actor
	ActorEmail string `json:"actor_email"`
	// ActorType: type of the actor
	ActorType string `json:"actor_type"`
	// id of the associate
	Associate string `json:"associate,omitempty"`
	// Type of the associate
	AssociateType string `json:"associate_type,omitempty"`
	// IP address of the request
	ClientIp string `json:"client_ip"`
	// The end time of the request
	EndTime string `json:"end_time"`
	// Region name of where the action is performed if applicable
	Location string `json:"location,omitempty"`
	// organization id
	OrganizationId string `json:"organization_id,omitempty"`
	// organization name
	OrganizationName string `json:"organization_name,omitempty"`
	// Project ID
	ProjectId string `json:"project_id,omitempty"`
	// Project Name
	ProjectName string `json:"project_name,omitempty"`
	// The status of the action
	Status string `json:"status"`
	// The start time of the request
	String_ string `json:"string"`
	// Surface type of the request
	Surface string `json:"surface"`
	// The targets of the action required
	Target string `json:"target,omitempty"`
	// The target names of the action
	TargetName string `json:"target_name,omitempty"`
	// The target type of the action required
	TargetType string `json:"target_type,omitempty"`
}
