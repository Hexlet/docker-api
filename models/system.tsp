import "@typespec/http";
import "@typespec/openapi";

import "./common.tsp";
import "./containers.tsp";
import "./images.tsp";
import "./swarm.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** Response of Engine API: GET "/version" */
model SystemVersion {
  Platform?: {
    Name: string;
  };
  /** Information about system components */
  Components?: ({
    Name: string;
    Version: string;
    Details?: Record<unknown> | null;
  })[];
  /** The version of the daemon */
  Version?: string;
  /** The default (and highest) API version that is supported by the daemon */
  ApiVersion?: string;
  /** The minimum API version that is supported by the daemon */
  MinAPIVersion?: string;
  /** The Git commit of the source code that was used to build the daemon */
  GitCommit?: string;
  /**
   * The version Go used to compile the daemon, and the version of the Go
   * runtime in use.
   */
  GoVersion?: string;
  /** The operating system that the daemon is running on ("linux" or "windows") */
  Os?: string;
  /**
   * Architecture of the daemon, as returned by the Go runtime (`GOARCH`).
   *
   * A full list of possible values can be found in the [Go documentation](https://go.dev/doc/install/source#environment).
   */
  Arch?: string;
  /**
   * The kernel version (`uname -r`) that the daemon is running on.
   *
   * This field is omitted when empty.
   */
  KernelVersion?: string;
  /**
   * Indicates if the daemon is started with experimental features enabled.
   *
   * This field is omitted when empty / false.
   */
  Experimental?: boolean;
  /** The date and time that the daemon was compiled. */
  BuildTime?: string;
}

model SystemInfo {
  /**
   * Unique identifier of the daemon.
   *
   * <p><br /></p>
   *
   * > **Note**: The format of the ID itself is not part of the API, and
   * > should not be considered stable.
   */
  ID?: string;
  /** Total number of containers on the host. */
  Containers?: int32;
  /** Number of containers with status `"running"`. */
  ContainersRunning?: int32;
  /** Number of containers with status `"paused"`. */
  ContainersPaused?: int32;
  /** Number of containers with status `"stopped"`. */
  ContainersStopped?: int32;
  /**
   * Total number of images on the host.
   *
   * Both _tagged_ and _untagged_ (dangling) images are counted.
   */
  Images?: int32;
  /** Name of the storage driver in use. */
  Driver?: string;
  /**
   * Information specific to the storage driver, provided as
   * "label" / "value" pairs.
   *
   * This information is provided by the storage driver, and formatted
   * in a way consistent with the output of `docker info` on the command
   * line.
   *
   * <p><br /></p>
   *
   * > **Note**: The information returned in this field, including the
   * > formatting of values and labels, should not be considered stable,
   * > and may change without notice.
   */
  DriverStatus?: string[][];
  /**
   * Root directory of persistent Docker state.
   *
   * Defaults to `/var/lib/docker` on Linux, and `C:\ProgramData\docker`
   * on Windows.
   */
  DockerRootDir?: string;
  Plugins?: PluginsInfo;
  /** Indicates if the host has memory limit support enabled. */
  MemoryLimit?: boolean;
  /** Indicates if the host has memory swap limit support enabled. */
  SwapLimit?: boolean;
  /**
   * Indicates if CPU CFS(Completely Fair Scheduler) period is supported by
   * the host.
   */
  CpuCfsPeriod?: boolean;
  /**
   * Indicates if CPU CFS(Completely Fair Scheduler) quota is supported by
   * the host.
   */
  CpuCfsQuota?: boolean;
  /** Indicates if CPU Shares limiting is supported by the host. */
  CPUShares?: boolean;
  /**
   * Indicates if CPUsets (cpuset.cpus, cpuset.mems) are supported by the host.
   *
   * See [cpuset(7)](https://www.kernel.org/doc/Documentation/cgroup-v1/cpusets.txt)
   */
  CPUSet?: boolean;
  /** Indicates if the host kernel has PID limit support enabled. */
  PidsLimit?: boolean;
  /** Indicates if OOM killer disable is supported on the host. */
  OomKillDisable?: boolean;
  /** Indicates IPv4 forwarding is enabled. */
  IPv4Forwarding?: boolean;
  /**
   * Indicates if the daemon is running in debug-mode / with debug-level
   * logging enabled.
   */
  Debug?: boolean;
  /**
   * The total number of file Descriptors in use by the daemon process.
   *
   * This information is only returned if debug-mode is enabled.
   */
  NFd?: int32;
  /**
   * The  number of goroutines that currently exist.
   *
   * This information is only returned if debug-mode is enabled.
   */
  NGoroutines?: int32;
  /**
   * Current system-time in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt)
   * format with nano-seconds.
   */
  SystemTime?: string;
  /** The logging driver to use as a default for new containers. */
  LoggingDriver?: string;
  /** The driver to use for managing cgroups. */
  CgroupDriver?: "cgroupfs" | "systemd" | "none";
  /** The version of the cgroup. */
  CgroupVersion?: "1" | "2";
  /** Number of event listeners subscribed. */
  NEventsListener?: int32;
  /**
   * Kernel version of the host.
   *
   * On Linux, this information obtained from `uname`. On Windows this
   * information is queried from the <kbd>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\</kbd>
   * registry value, for example _"10.0 14393 (14393.1198.amd64fre.rs1_release_sec.170427-1353)"_.
   */
  KernelVersion?: string;
  /**
   * Name of the host's operating system, for example: "Ubuntu 24.04 LTS"
   * or "Windows Server 2016 Datacenter"
   */
  OperatingSystem?: string;
  /**
   * Version of the host's operating system
   *
   * <p><br /></p>
   *
   * > **Note**: The information returned in this field, including its
   * > very existence, and the formatting of values, should not be considered
   * > stable, and may change without notice.
   */
  OSVersion?: string;
  /**
   * Generic type of the operating system of the host, as returned by the
   * Go runtime (`GOOS`).
   *
   * Currently returned values are "linux" and "windows". A full list of
   * possible values can be found in the [Go documentation](https://go.dev/doc/install/source#environment).
   */
  OSType?: string;
  /**
   * Hardware architecture of the host, as returned by the operating system.
   * This is equivalent to the output of `uname -m` on Linux.
   *
   * Unlike `Arch` (from `/version`), this reports the machine's native
   * architecture, which can differ from the Go runtime architecture when
   * running a binary compiled for a different architecture (for example,
   * a 32-bit binary running on 64-bit hardware).
   */
  Architecture?: string;
  /**
   * The number of logical CPUs usable by the daemon.
   *
   * The number of available CPUs is checked by querying the operating
   * system when the daemon starts. Changes to operating system CPU
   * allocation after the daemon is started are not reflected.
   */
  NCPU?: int32;
  /** Total amount of physical memory available on the host, in bytes. */
  MemTotal?: int64;
  /**
   * Address / URL of the index server that is used for image search,
   * and as a default for user authentication for Docker Hub and Docker Cloud.
   */
  IndexServerAddress?: string;
  RegistryConfig?: RegistryServiceConfig;
  GenericResources?: GenericResources;
  /**
   * HTTP-proxy configured for the daemon. This value is obtained from the
   * [`HTTP_PROXY`](https://www.gnu.org/software/wget/manual/html_node/Proxies.html) environment variable.
   * Credentials ([user info component](https://tools.ietf.org/html/rfc3986#section-3.2.1)) in the proxy URL
   * are masked in the API response.
   *
   * Containers do not automatically inherit this configuration.
   */
  HttpProxy?: string;
  /**
   * HTTPS-proxy configured for the daemon. This value is obtained from the
   * [`HTTPS_PROXY`](https://www.gnu.org/software/wget/manual/html_node/Proxies.html) environment variable.
   * Credentials ([user info component](https://tools.ietf.org/html/rfc3986#section-3.2.1)) in the proxy URL
   * are masked in the API response.
   *
   * Containers do not automatically inherit this configuration.
   */
  HttpsProxy?: string;
  /**
   * Comma-separated list of domain extensions for which no proxy should be
   * used. This value is obtained from the [`NO_PROXY`](https://www.gnu.org/software/wget/manual/html_node/Proxies.html)
   * environment variable.
   *
   * Containers do not automatically inherit this configuration.
   */
  NoProxy?: string;
  /** Hostname of the host. */
  Name?: string;
  /**
   * User-defined labels (key/value metadata) as set on the daemon.
   *
   * <p><br /></p>
   *
   * > **Note**: When part of a Swarm, nodes can both have _daemon_ labels,
   * > set through the daemon configuration, and _node_ labels, set from a
   * > manager node in the Swarm. Node labels are not included in this
   * > field. Node labels can be retrieved using the `/nodes/(id)` endpoint
   * > on a manager node in the Swarm.
   */
  Labels?: string[];
  /** Indicates if experimental features are enabled on the daemon. */
  ExperimentalBuild?: boolean;
  /** Version string of the daemon. */
  ServerVersion?: string;
  /**
   * List of [OCI compliant](https://github.com/opencontainers/runtime-spec)
   * runtimes configured on the daemon. Keys hold the "name" used to
   * reference the runtime.
   *
   * The Docker daemon relies on an OCI compliant runtime (invoked via the
   * `containerd` daemon) as its interface to the Linux kernel namespaces,
   * cgroups, and SELinux.
   *
   * The default runtime is `runc`, and automatically configured. Additional
   * runtimes can be configured by the user and will be listed here.
   */
  Runtimes?: Record<Runtime>;
  /**
   * Name of the default OCI runtime that is used when starting containers.
   *
   * The default can be overridden per-container at create time.
   */
  DefaultRuntime?: string;
  Swarm?: SwarmInfo;
  /**
   * Indicates if live restore is enabled.
   *
   * If enabled, containers are kept running when the daemon is shutdown
   * or upon daemon start if running containers are detected.
   */
  LiveRestoreEnabled?: boolean;
  /**
   * Represents the isolation technology to use as a default for containers.
   * The supported values are platform-specific.
   *
   * If no isolation value is specified on daemon start, on Windows client,
   * the default is `hyperv`, and on Windows server, the default is `process`.
   *
   * This option is currently not used on other platforms.
   */
  Isolation?: "default" | "hyperv" | "process" | "";
  /**
   * Name and, optional, path of the `docker-init` binary.
   *
   * If the path is omitted, the daemon searches the host's `$PATH` for the
   * binary and uses the first result.
   */
  InitBinary?: string;
  ContainerdCommit?: Commit;
  RuncCommit?: Commit;
  InitCommit?: Commit;
  /**
   * List of security features that are enabled on the daemon, such as
   * apparmor, seccomp, SELinux, user-namespaces (userns), rootless and
   * no-new-privileges.
   *
   * Additional configuration options for each security feature may
   * be present, and are included as a comma-separated list of key/value
   * pairs.
   */
  SecurityOptions?: string[];
  /**
   * Reports a summary of the product license on the daemon.
   *
   * If a commercial license has been applied to the daemon, information
   * such as number of nodes, and expiration are included.
   */
  ProductLicense?: string;
  /**
   * List of custom default address pools for local networks, which can be
   * specified in the daemon.json file or dockerd option.
   *
   * Example: a Base "10.10.0.0/16" with Size 24 will define the set of 256
   * 10.10.[0-255].0/24 address pools.
   */
  DefaultAddressPools?: {
    Base?: string;
    Size?: int32;
  }[];
  FirewallBackend?: FirewallInfo;
  /**
   * List of devices discovered by device drivers.
   *
   * Each device includes information about its source driver, kind, name,
   * and additional driver-specific attributes.
   */
  DiscoveredDevices?: DeviceInfo[];
  NRI?: NRIInfo;
  /**
   * List of warnings / informational messages about missing features, or
   * issues related to the daemon configuration.
   *
   * These messages can be printed by the client as information to the user.
   */
  Warnings?: string[];
  /**
   * List of directories where (Container Device Interface) CDI
   * specifications are located.
   *
   * These specifications define vendor-specific modifications to an OCI
   * runtime specification for a container being created.
   *
   * An empty list indicates that CDI device injection is disabled.
   *
   * Note that since using CDI device injection requires the daemon to have
   * experimental enabled. For non-experimental daemons an empty list will
   * always be returned.
   */
  CDISpecDirs?: string[];
  Containerd?: ContainerdInfo;
}

/**
 * Information for connecting to the containerd instance that is used by the daemon.
 * This is included for debugging purposes only.
 */
model ContainerdInfo {
  /** The address of the containerd socket. */
  Address?: string;
  /**
   * The namespaces that the daemon uses for running containers and
   * plugins in containerd. These namespaces can be configured in the
   * daemon configuration, and are considered to be used exclusively
   * by the daemon, Tampering with the containerd instance may cause
   * unexpected behavior.
   *
   * As these namespaces are considered to be exclusively accessed
   * by the daemon, it is not recommended to change these values,
   * or to change them to a value that is used by other systems,
   * such as cri-containerd.
   */
  Namespaces?: {
    Containers?: string;
    Plugins?: string;
  };
}

/**
 * Information about the daemon's firewalling configuration.
 *
 * This field is currently only used on Linux, and omitted on other platforms.
 */
model FirewallInfo {
  /** The name of the firewall backend driver. */
  Driver?: string;
  /**
   * Information about the firewall backend, provided as
   * "label" / "value" pairs.
   *
   * <p><br /></p>
   *
   * > **Note**: The information returned in this field, including the
   * > formatting of values and labels, should not be considered stable,
   * > and may change without notice.
   */
  Info?: string[][];
}

/**
 * Information about the Node Resource Interface (NRI).
 *
 * This field is only present if NRI is enabled.
 */
model NRIInfo {
  /**
   * Information about NRI, provided as "label" / "value" pairs.
   *
   * <p><br /></p>
   *
   * > **Note**: The information returned in this field, including the
   * > formatting of values and labels, should not be considered stable,
   * > and may change without notice.
   */
  Info?: string[][];
}

/** DeviceInfo represents a device that can be used by a container. */
model DeviceInfo {
  /** The origin device driver. */
  Source?: string;
  /**
   * The unique identifier for the device within its source driver.
   * For CDI devices, this would be an FQDN like "vendor.com/gpu=0".
   */
  ID?: string;
}

/**
 * Available plugins per type.
 *
 * <p><br /></p>
 *
 * > **Note**: Only unmanaged (V1) plugins are included in this list.
 * > V1 plugins are "lazily" loaded, and are not returned in this list
 * > if there is no resource using the plugin.
 */
model PluginsInfo {
  /** Names of available volume-drivers, and network-driver plugins. */
  Volume?: string[];
  /** Names of available network-drivers, and network-driver plugins. */
  Network?: string[];
  /** Names of available authorization plugins. */
  Authorization?: string[];
  /** Names of available logging-drivers, and logging-driver plugins. */
  Log?: string[];
}

/** RegistryServiceConfig stores daemon registry services configuration. */
model RegistryServiceConfig {
  /**
   * List of IP ranges of insecure registries, using the CIDR syntax
   * ([RFC 4632](https://tools.ietf.org/html/4632)). Insecure registries
   * accept un-encrypted (HTTP) and/or untrusted (HTTPS with certificates
   * from unknown CAs) communication.
   *
   * By default, local registries (`::1/128` and `127.0.0.0/8`) are configured as
   * insecure. All other registries are secure. Communicating with an
   * insecure registry is not possible if the daemon assumes that registry
   * is secure.
   *
   * This configuration override this behavior, insecure communication with
   * registries whose resolved IP address is within the subnet described by
   * the CIDR syntax.
   *
   * Registries can also be marked insecure by hostname. Those registries
   * are listed under `IndexConfigs` and have their `Secure` field set to
   * `false`.
   *
   * > **Warning**: Using this option can be useful when running a local
   * > registry, but introduces security vulnerabilities. This option
   * > should therefore ONLY be used for testing purposes. For increased
   * > security, users should add their CA to their system's list of trusted
   * > CAs instead of enabling this option.
   */
  InsecureRegistryCIDRs?: string[];
  IndexConfigs?: Record<IndexInfo>;
  /**
   * List of registry URLs that act as a mirror for the official
   * (`docker.io`) registry.
   */
  Mirrors?: string[];
}

/** IndexInfo contains information about a registry. */
model IndexInfo {
  /** Name of the registry, such as "docker.io". */
  Name?: string;
  /** List of mirrors, expressed as URIs. */
  Mirrors?: string[];
  /**
   * Indicates if the registry is part of the list of insecure
   * registries.
   *
   * If `false`, the registry is insecure. Insecure registries accept
   * un-encrypted (HTTP) and/or untrusted (HTTPS with certificates from
   * unknown CAs) communication.
   *
   * > **Warning**: Insecure registries can be useful when running a local
   * > registry. However, because its use creates security vulnerabilities
   * > it should ONLY be enabled for testing purposes. For increased
   * > security, users should add their CA to their system's list of
   * > trusted CAs instead of enabling this option.
   */
  Secure?: boolean;
  /** Indicates whether this is an official registry (i.e., Docker Hub / docker.io) */
  Official?: boolean;
}

/**
 * Runtime describes an [OCI compliant](https://github.com/opencontainers/runtime-spec)
 * runtime.
 *
 * The runtime is invoked by the daemon via the `containerd` daemon. OCI
 * runtimes act as an interface to the Linux kernel namespaces, cgroups,
 * and SELinux.
 */
model Runtime {
  /**
   * Name and, optional, path, of the OCI executable binary.
   *
   * If the path is omitted, the daemon searches the host's `$PATH` for the
   * binary and uses the first result.
   */
  path?: string;
  /** List of command-line arguments to pass to the runtime when invoked. */
  runtimeArgs?: string[] | null;
  /**
   * Information specific to the runtime.
   *
   * While this API specification does not define data provided by runtimes,
   * the following well-known properties may be provided by runtimes:
   *
   * `org.opencontainers.runtime-spec.features`: features structure as defined
   * in the [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec/blob/main/features.md),
   * in a JSON string representation.
   *
   * <p><br /></p>
   *
   * > **Note**: The information returned in this field, including the
   * > formatting of values and labels, should not be considered stable,
   * > and may change without notice.
   */
  status?: Record<string> | null;
}

/** EventMessage represents the information an event contains. */
model EventMessage {
  /** The type of object emitting the event */
  Type?: "builder" | "config" | "container" | "daemon" | "image" | "network" | "node" | "plugin" | "secret" | "service" | "volume";
  /** The type of event */
  Action?: string;
  Actor?: EventActor;
  /**
   * Scope of the event. Engine events are `local` scope. Cluster (Swarm)
   * events are `swarm` scope.
   */
  scope?: "local" | "swarm";
  /** Timestamp of event */
  time?: int64;
  /** Timestamp of event, with nanosecond accuracy */
  timeNano?: int64;
}

/**
 * Actor describes something that generates events, like a container, network,
 * or a volume.
 */
model EventActor {
  /** The ID of the object emitting the event */
  ID?: string;
  /** Various key/value attributes of the object, depending on its type. */
  Attributes?: Record<string>;
}

/**
 * Describes the result obtained from contacting the registry to retrieve
 * image metadata.
 */
model DistributionInspect {
  Descriptor: OCIDescriptor;
  /** An array containing all platforms supported by the image. */
  Platforms: OCIPlatform[];
}
