import "@typespec/http";
import "@typespec/openapi";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

model Network {
  /** Name of the network. */
  Name?: string;
  /** ID that uniquely identifies a network on a single machine. */
  Id?: string;
  /**
   * Date and time at which the network was created in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  Created?: utcDateTime;
  /**
   * The level at which the network exists (e.g. `swarm` for cluster-wide
   * or `local` for machine level)
   */
  Scope?: string;
  /**
   * The name of the driver used to create the network (e.g. `bridge`,
   * `overlay`).
   */
  Driver?: string;
  /** Whether the network was created with IPv4 enabled. */
  EnableIPv4?: boolean;
  /** Whether the network was created with IPv6 enabled. */
  EnableIPv6?: boolean;
  /** The network's IP Address Management. */
  IPAM?: IPAM;
  /**
   * Whether the network is created to only allow internal networking
   * connectivity.
   */
  Internal?: boolean;
  /**
   * Whether a global / swarm scope network is manually attachable by regular
   * containers from workers in swarm mode.
   */
  Attachable?: boolean;
  /** Whether the network is providing the routing-mesh for the swarm cluster. */
  Ingress?: boolean;
  ConfigFrom?: ConfigReference;
  /**
   * Whether the network is a config-only network. Config-only networks are
   * placeholder networks for network configurations to be used by other
   * networks. Config-only networks cannot be used directly to run containers
   * or services.
   */
  ConfigOnly?: boolean;
  /** Network-specific options uses when creating the network. */
  Options?: Record<string>;
  /** Metadata specific to the network being created. */
  Labels?: Record<string>;
  /**
   * List of peer nodes for an overlay network. This field is only present
   * for overlay networks, and omitted for other network types.
   */
  Peers?: PeerInfo[];
}

/** Network list response item */
model NetworkSummary {
  ...Network;
}

/** The body of the "get network" http response message. */
model NetworkInspect {
  ...Network;
}

/**
 * provides runtime information about the network such as the number of allocated IPs.
 */
model NetworkStatus {
  IPAM?: IPAMStatus;
}

/** represents service parameters with the list of service's tasks */
model ServiceInfo {
  VIP?: string;
  Ports?: string[];
  LocalLBIndex?: int32;
  Tasks?: NetworkTaskInfo[];
}

/** carries the information about one backend task */
model NetworkTaskInfo {
  Name?: string;
  EndpointID?: string;
  EndpointIP?: string;
  Info?: Record<string>;
}

model IPAM {
  /** Name of the IPAM driver to use. */
  Driver?: string;
  /**
   * List of IPAM configuration options, specified as a map:
   *
   * ```
   * {"Subnet": <CIDR>, "IPRange": <CIDR>, "Gateway": <IP address>, "AuxAddress": <device_name:IP address>}
   * ```
   */
  Config?: IPAMConfig[];
  /** Driver-specific options, specified as a map. */
  Options?: Record<string>;
}

model IPAMConfig {
  Subnet?: string;
  IPRange?: string;
  Gateway?: string;
  AuxiliaryAddresses?: Record<string>;
}

model IPAMStatus {
  Subnets?: Record<SubnetStatus>;
}

model SubnetStatus {
  /**
   * Number of IP addresses in the subnet that are in use or reserved and are therefore unavailable for allocation, saturating at 2<sup>64</sup> - 1.
   */
  IPsInUse?: uint64;
  /**
   * Number of IP addresses within the network's IPRange for the subnet that are available for allocation, saturating at 2<sup>64</sup> - 1.
   */
  DynamicIPsAvailable?: uint64;
}

/** contains network resources allocated and used for a container in a network. */
model EndpointResource {
  Name?: string;
  EndpointID?: string;
  MacAddress?: string;
  IPv4Address?: string;
  IPv6Address?: string;
}

/** represents one peer of an overlay network. */
model PeerInfo {
  /** ID of the peer-node in the Swarm cluster. */
  Name?: string;
  /** IP-address of the peer-node in the Swarm cluster. */
  IP?: string;
}

/** OK response to NetworkCreate operation */
model NetworkCreateResponse {
  /** The ID of the created network. */
  Id: string;
  /** Warnings encountered when creating the container */
  Warning: string;
}

/**
 * NetworkConnectRequest represents the data to be used to connect a container to a network.
 */
model NetworkConnectRequest {
  /** The ID or name of the container to connect to the network. */
  Container: string;
  EndpointConfig?: EndpointSettings | null;
}

/**
 * NetworkDisconnectRequest represents the data to be used to disconnect a container from a network.
 */
model NetworkDisconnectRequest {
  /** The ID or name of the container to disconnect from the network. */
  Container: string;
  /** Force the container to disconnect from the network. */
  Force?: boolean;
}

/** Configuration for a network endpoint. */
model EndpointSettings {
  IPAMConfig?: EndpointIPAMConfig;
  Links?: string[];
  /**
   * MAC address for the endpoint on this network. The network driver might ignore this parameter.
   */
  MacAddress?: string;
  Aliases?: string[];
  /**
   * DriverOpts is a mapping of driver options and values. These options
   * are passed directly to the driver and are driver specific.
   */
  DriverOpts?: Record<string> | null;
  /**
   * This property determines which endpoint will provide the default
   * gateway for a container. The endpoint with the highest priority will
   * be used. If multiple endpoints have the same priority, endpoints are
   * lexicographically sorted based on their network name, and the one
   * that sorts first is picked.
   */
  GwPriority?: int64;
  /** Unique ID of the network. */
  NetworkID?: string;
  /** Unique ID for the service endpoint in a Sandbox. */
  EndpointID?: string;
  /** Gateway address for this network. */
  Gateway?: string;
  /** IPv4 address. */
  IPAddress?: string;
  /** Mask length of the IPv4 address. */
  IPPrefixLen?: int32;
  /** IPv6 gateway address. */
  IPv6Gateway?: string;
  /** Global IPv6 address. */
  GlobalIPv6Address?: string;
  /** Mask length of the global IPv6 address. */
  GlobalIPv6PrefixLen?: int64;
  /**
   * List of all DNS names an endpoint has on a specific network. This
   * list is based on the container name, network aliases, container short
   * ID, and hostname.
   *
   * These DNS names are non-fully qualified but can contain several dots.
   * You can get fully qualified DNS names by appending `.<network-name>`.
   * For instance, if container name is `my.ctr` and the network is named
   * `testnet`, `DNSNames` will contain `my.ctr` and the FQDN will be
   * `my.ctr.testnet`.
   */
  DNSNames?: string[];
}

/** EndpointIPAMConfig represents an endpoint's IPAM configuration. */
model EndpointIPAMConfig {
  IPv4Address?: string;
  IPv6Address?: string;
  LinkLocalIPs?: string[];
}

/** Describes a port-mapping between the container and the host. */
model PortSummary {
  /** Host IP address that the container's port is mapped to */
  IP?: string;
  /** Port on the container */
  PrivatePort: uint16;
  /** Port exposed on the host */
  PublicPort?: uint16;
  Type: "tcp" | "udp" | "sctp";
}

/**
 * PortMap describes the mapping of container ports to host ports, using the
 * container's port-number and protocol as key in the format `<port>/<protocol>`,
 * for example, `80/udp`.
 *
 * If a container's port is mapped for multiple protocols, separate entries
 * are added to the mapping table.
 */
alias PortMap = Record<PortBinding[]>;

/**
 * PortBinding represents a binding between a host IP address and a host
 * port.
 */
model PortBinding {
  /** Host IP address that the container's port is mapped to. */
  HostIp?: string;
  /** Host port number that the container's port is mapped to. */
  HostPort?: string;
}

/** Address represents an IPv4 or IPv6 IP address. */
model Address {
  /** IP address. */
  Addr?: string;
  /** Mask length of the IP address. */
  PrefixLen?: int32;
}

/** Specifies how a service should be attached to a particular network. */
model NetworkAttachmentConfig {
  /** The target network for attachment. Must be a network name or ID. */
  Target?: string;
  /** Discoverable alternate names for the service on this network. */
  Aliases?: string[];
  /** Driver attachment options for the network target. */
  DriverOpts?: Record<string>;
}

/**
 * The config-only network source to provide the configuration for
 * this network.
 */
model ConfigReference {
  /**
   * The name of the config-only network that provides the network's
   * configuration. The specified network must be an existing config-only
   * network. Only network names are allowed, not network IDs.
   */
  Network?: string;
}
