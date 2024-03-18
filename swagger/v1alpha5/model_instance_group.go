/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type InstanceGroup struct {
	// Time the instance template was created.
	CreatedAt string `json:"created_at"`
	// ID of the instance group.
	Id string `json:"id"`
	// A list of IDs of instances currently in the instance group.
	Instances []string `json:"instances"`
	// Name of the instance group.
	Name string `json:"name"`
	// Project ID of the project this instance template belongs to.
	ProjectId string `json:"project_id"`
	// The number of running instances currently in the Instance Group.
	RunningInstanceCount int64 `json:"running_instance_count"`
	// Instance Template ID currently associated with the instance group.
	TemplateId string `json:"template_id"`
	// Most recent time the instance group was updated.
	UpdatedAt string `json:"updated_at"`
}
