/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type VpcFirewallRulesPostRequestV1Alpha5 struct {
	Action           string               `json:"action"`
	DestinationPorts []string             `json:"destination_ports,omitempty"`
	Destinations     []FirewallRuleObject `json:"destinations"`
	Direction        string               `json:"direction"`
	Name             string               `json:"name"`
	ProjectId        string               `json:"project_id"`
	Protocols        []string             `json:"protocols"`
	SourcePorts      []string             `json:"source_ports,omitempty"`
	Sources          []FirewallRuleObject `json:"sources"`
	VpcNetworkId     string               `json:"vpc_network_id"`
}
