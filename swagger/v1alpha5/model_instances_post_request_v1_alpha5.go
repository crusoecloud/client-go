/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

// InstancesPostRequestV1Alpha5 is the request type for POST requests to the vms.instances endpoint.
type InstancesPostRequestV1Alpha5 struct {
	CommitmentPeriod       int64                       `json:"commitment_period,omitempty"`
	Disks                  []DiskAttachment            `json:"disks,omitempty"`
	HostChannelAdapters    []PartialHostChannelAdapter `json:"host_channel_adapters,omitempty"`
	Image                  string                      `json:"image,omitempty"`
	Location               string                      `json:"location,omitempty"`
	Name                   string                      `json:"name"`
	NetworkInterfaces      []NetworkInterface          `json:"network_interfaces,omitempty"`
	ReservationId          string                      `json:"reservation_id,omitempty"`
	ShutdownScript         string                      `json:"shutdown_script,omitempty"`
	SshPublicKey           string                      `json:"ssh_public_key"`
	StartupScript          string                      `json:"startup_script,omitempty"`
	Type_                  string                      `json:"type"`
	VirtualizationFeatures *VirtualizationFeatures     `json:"virtualization_features,omitempty"`
}
