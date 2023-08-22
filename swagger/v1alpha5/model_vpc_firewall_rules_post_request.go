/*
 * Crusoe Cloud API Gateway
 *
 * The API Gateway exposes all publicly available API endpoints for Crusoe Cloud products.
 *
 * API version: v1alpha5
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type VpcFirewallRulesPostRequest struct {
	Action           string               `json:"action"`
	DestinationPorts []string             `json:"destination_ports,omitempty"`
	Destinations     []FirewallRuleObject `json:"destinations"`
	Direction        string               `json:"direction"`
	Name             string               `json:"name"`
	Protocols        []string             `json:"protocols"`
	RoleId           string               `json:"role_id"`
	SourcePorts      []string             `json:"source_ports,omitempty"`
	Sources          []FirewallRuleObject `json:"sources"`
	VpcNetworkId     string               `json:"vpc_network_id"`
}
