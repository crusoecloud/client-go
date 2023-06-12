/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha3
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// InstancesDetachDiskPostRequest is the request type for POST requests to the vms.instances.detach-disk endpoint.
type InstancesDetachDiskPostRequest struct {
	DetachDisks []string `json:"detach_disks"`
}
