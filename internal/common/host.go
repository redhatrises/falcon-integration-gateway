// Package common holds domain types shared across the gateway's layers. Keeping
// them here lets the low-level Falcon client and the higher-level events/backends
// packages agree on a single representation without importing each other.
package common

// HostDetails is the normalized subset of Falcon device details the pipeline and
// enrichment-consuming backends need. It mirrors the projection the Python
// gateway read from GetDeviceDetailsV2 (service_provider, service_provider_
// account_id, instance_id, platform_name), plus the device/sensor identifiers
// and the host attributes the AWS Security Hub finding payload reports (host
// name, network addresses, domain, agent/OS versions, last-seen, tags, site, OU).
//
// Known and SensorID are enrichment state, not fields the device API returns: a
// raw client.DeviceDetails fetch leaves them zero, and the enricher sets them
// once it confirms the sensor resolves to exactly one device. Known therefore
// distinguishes a successful lookup that resolved to a real device from the
// empty-provider fallback used when a device cannot be identified.
//
// An Enricher may cache and return the same *HostDetails to concurrent callers,
// so a value obtained from one is read-only by contract: callers must not mutate
// its fields (including the Tags and OU slices).
type HostDetails struct {
	Known                  bool
	DeviceID               string
	SensorID               string
	Hostname               string
	CloudProvider          string
	CloudProviderAccountID string
	InstanceID             string
	Platform               string
	MACAddress             string
	ExternalIP             string
	LocalIP                string
	MachineDomain          string
	AgentVersion           string
	LastSeen               string
	OSVersion              string
	SiteName               string
	OU                     []string
	Tags                   []string
	ProductTypeDesc        string
	ZoneGroup              string
}
