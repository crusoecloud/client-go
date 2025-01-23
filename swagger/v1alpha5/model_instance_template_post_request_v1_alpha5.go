/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type InstanceTemplatePostRequestV1Alpha5 struct {
	// Custom image to use for all VMs created from this instance template. Only one of Image or CustomImage should be supplied at once.
	CustomImageName string `json:"custom_image_name,omitempty"`
	// Disks to create for all VMs created from this instance template.
	Disks []DiskTemplate `json:"disks,omitempty"`
	// IB Partition to use for all VMs created from this instance template. Should only be provided for IB-enabled VM types. This is location-specific and must be provided if location is provided.
	IbPartitionId string `json:"ib_partition_id,omitempty"`
	// OS Image to use for all VMs created from this instance template.
	ImageName string `json:"image_name,omitempty"`
	// Location to use for all VMs created from this instance template. If provided, all location-specific resources must also be provided.
	Location string `json:"location,omitempty"`
	// THe Host Maintenance Policy to use.
	MaintenancePolicy string `json:"maintenance_policy,omitempty"`
	// The VM Placement Policy to use.
	PlacementPolicy string `json:"placement_policy,omitempty"`
	// Public IP address type to use for all VMs created from this instance template. Must either be \"static\" or \"dynamic\".
	PublicIpAddressType string `json:"public_ip_address_type,omitempty"`
	ReservationId       string `json:"reservation_id,omitempty"`
	// Shutdown script to use for all VMs created from this instance template.
	ShutdownScript string `json:"shutdown_script,omitempty"`
	// SSH public key to use for all VMs created from this instance template.
	SshPublicKey string `json:"ssh_public_key"`
	// Startup script to use for all VMs created from this instance template.
	StartupScript string `json:"startup_script,omitempty"`
	// Subnet to use for all VMs created from this instance template. This is location-specific and must be provided if location is provided.
	SubnetId string `json:"subnet_id,omitempty"`
	// Name of the instance template. (This is not the name of the VMs created from this instance template.)
	TemplateName string `json:"template_name"`
	// Product name of the VM type we want to create from this instance template.
	Type_                  string                  `json:"type"`
	VirtualizationFeatures *VirtualizationFeatures `json:"virtualization_features,omitempty"`
}
