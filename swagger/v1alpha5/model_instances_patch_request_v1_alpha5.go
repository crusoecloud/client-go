/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type InstancesPatchRequestV1Alpha5 struct {
	Action              string                      `json:"action"`
	CommitmentPeriod    int64                       `json:"commitment_period,omitempty"`
	HostChannelAdapters []PartialHostChannelAdapter `json:"host_channel_adapters,omitempty"`
	NetworkInterfaces   []NetworkInterface          `json:"network_interfaces,omitempty"`
	ReservationId       string                      `json:"reservation_id,omitempty"`
	Type_               string                      `json:"type,omitempty"`
}
