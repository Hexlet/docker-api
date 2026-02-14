import "@typespec/http";
import "@typespec/openapi";

import "./images.tsp";
import "./mounts.tsp";
import "./networks.tsp";
import "./volumes.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** Configuration for a container that is portable between hosts. */
model ContainerConfig {
  /** The hostname to use for the container, as a valid RFC 1123 hostname. */
  Hostname?: string;
  /** The domain name to use for the container. */
  Domainname?: string;
  /**
   * Commands run as this user inside the container. If omitted, commands
   * run as the user specified in the image the container was started from.
   *
   * Can be either user-name or UID, and optional group-name or GID,
   * separated by a colon (`<user-name|UID>[<:group-name|GID>]`).
   */
  User?: string;
  /** Whether to attach to `stdin`. */
  AttachStdin?: boolean;
  /** Whether to attach to `stdout`. */
  AttachStdout?: boolean;
  /** Whether to attach to `stderr`. */
  AttachStderr?: boolean;
  /**
   * An object mapping ports to an empty object in the form:
   *
   * `{"<port>/<tcp|udp|sctp>": {}}`
   */
  ExposedPorts?: Record<Record<unknown>> | null;
  /** Attach standard streams to a TTY, including `stdin` if it is not closed. */
  Tty?: boolean;
  /** Open `stdin` */
  OpenStdin?: boolean;
  /** Close `stdin` after one attached client disconnects */
  StdinOnce?: boolean;
  /**
   * A list of environment variables to set inside the container in the
   * form `["VAR=value", ...]`. A variable without `=` is removed from the
   * environment, rather than to have an empty value.
   */
  Env?: string[];
  /** Command to run specified as a string or an array of strings. */
  Cmd?: string[];
  Healthcheck?: HealthConfig;
  /** Command is already escaped (Windows only) */
  ArgsEscaped?: boolean | null;
  /**
   * The name (or reference) of the image to use when creating the container,
   * or which was used when the container was created.
   */
  Image?: string;
  /**
   * An object mapping mount point paths inside the container to empty
   * objects.
   */
  Volumes?: Record<Record<unknown>>;
  /** The working directory for commands to run in. */
  WorkingDir?: string;
  /**
   * The entry point for the container as a string or an array of strings.
   *
   * If the array consists of exactly one empty string (`[""]`) then the
   * entry point is reset to system default (i.e., the entry point used by
   * docker when there is no `ENTRYPOINT` instruction in the `Dockerfile`).
   */
  Entrypoint?: string[];
  /** Disable networking for the container. */
  NetworkDisabled?: boolean | null;
  /** `ONBUILD` metadata that were defined in the image's `Dockerfile`. */
  OnBuild?: string[] | null;
  /** User-defined key/value metadata. */
  Labels?: Record<string>;
  /** Signal to stop a container as a string or unsigned integer. */
  StopSignal?: string | null;
  /** Timeout to stop a container in seconds. */
  StopTimeout?: int32 | null;
  /** Shell for when `RUN`, `CMD`, and `ENTRYPOINT` uses a shell. */
  Shell?: string[] | null;
}

/**
 * Configuration of the image. These fields are used as defaults
 * when starting a container from the image.
 */
model ImageConfig {
  /** The user that commands are run as inside the container. */
  User?: string;
  /**
   * An object mapping ports to an empty object in the form:
   *
   * `{"<port>/<tcp|udp|sctp>": {}}`
   */
  ExposedPorts?: Record<Record<unknown>> | null;
  /**
   * A list of environment variables to set inside the container in the
   * form `["VAR=value", ...]`. A variable without `=` is removed from the
   * environment, rather than to have an empty value.
   */
  Env?: string[];
  /** Command to run specified as a string or an array of strings. */
  Cmd?: string[];
  Healthcheck?: HealthConfig;
  /** Command is already escaped (Windows only) */
  ArgsEscaped?: boolean | null;
  /**
   * An object mapping mount point paths inside the container to empty
   * objects.
   */
  Volumes?: Record<Record<unknown>>;
  /** The working directory for commands to run in. */
  WorkingDir?: string;
  /**
   * The entry point for the container as a string or an array of strings.
   *
   * If the array consists of exactly one empty string (`[""]`) then the
   * entry point is reset to system default (i.e., the entry point used by
   * docker when there is no `ENTRYPOINT` instruction in the `Dockerfile`).
   */
  Entrypoint?: string[];
  /** `ONBUILD` metadata that were defined in the image's `Dockerfile`. */
  OnBuild?: string[] | null;
  /** User-defined key/value metadata. */
  Labels?: Record<string>;
  /** Signal to stop a container as a string or unsigned integer. */
  StopSignal?: string | null;
  /** Shell for when `RUN`, `CMD`, and `ENTRYPOINT` uses a shell. */
  Shell?: string[] | null;
}

/** Container configuration that depends on the host we are running on */
model HostConfig {
  ...Resources;
  /**
   * A list of volume bindings for this container. Each volume binding
   * is a string in one of these forms:
   *
   * - `host-src:container-dest[:options]` to bind-mount a host path
   *   into the container. Both `host-src`, and `container-dest` must
   *   be an _absolute_ path.
   * - `volume-name:container-dest[:options]` to bind-mount a volume
   *   managed by a volume driver into the container. `container-dest`
   *   must be an _absolute_ path.
   *
   * `options` is an optional, comma-delimited list of:
   *
   * - `nocopy` disables automatic copying of data from the container
   *   path to the volume. The `nocopy` flag only applies to named volumes.
   * - `[ro|rw]` mounts a volume read-only or read-write, respectively.
   *   If omitted or set to `rw`, volumes are mounted read-write.
   * - `[z|Z]` applies SELinux labels to allow or deny multiple containers
   *   to read and write to the same volume.
   *     - `z`: a _shared_ content label is applied to the content. This
   *       label indicates that multiple containers can share the volume
   *       content, for both reading and writing.
   *     - `Z`: a _private unshared_ label is applied to the content.
   *       This label indicates that only the current container can use
   *       a private volume. Labeling systems such as SELinux require
   *       proper labels to be placed on volume content that is mounted
   *       into a container. Without a label, the security system can
   *       prevent a container's processes from using the content. By
   *       default, the labels set by the host operating system are not
   *       modified.
   * - `[[r]shared|[r]slave|[r]private]` specifies mount
   *   [propagation behavior](https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt).
   *   This only applies to bind-mounted volumes, not internal volumes
   *   or named volumes. Mount propagation requires the source mount
   *   point (the location where the source directory is mounted in the
   *   host operating system) to have the correct propagation properties.
   *   For shared volumes, the source mount point must be set to `shared`.
   *   For slave volumes, the mount must be set to either `shared` or
   *   `slave`.
   */
  Binds?: string[];
  /** Path to a file where the container ID is written */
  ContainerIDFile?: string;
  /** The logging configuration for this container */
  LogConfig?: {
    Type?: "local" | "json-file" | "syslog" | "journald" | "gelf" | "fluentd" | "awslogs" | "splunk" | "etwlogs" | "none";
    Config?: Record<string>;
  };
  /**
   * Network mode to use for this container. Supported standard values
   * are: `bridge`, `host`, `none`, and `container:<name|id>`. Any
   * other value is taken as a custom network's name to which this
   * container should connect to.
   */
  NetworkMode?: string;
  PortBindings?: PortMap;
  RestartPolicy?: RestartPolicy;
  /**
   * Automatically remove the container when the container's process
   * exits. This has no effect if `RestartPolicy` is set.
   */
  AutoRemove?: boolean;
  /** Driver that this container uses to mount volumes. */
  VolumeDriver?: string;
  /**
   * A list of volumes to inherit from another container, specified in
   * the form `<container name>[:<ro|rw>]`.
   */
  VolumesFrom?: string[];
  /** Specification for mounts to be added to the container. */
  Mounts?: Mount[];
  /** Initial console size, as an `[height, width]` array. */
  ConsoleSize?: int32[] | null;
  /**
   * Arbitrary non-identifying metadata attached to container and
   * provided to the runtime when the container is started.
   */
  Annotations?: Record<string>;
  /**
   * A list of kernel capabilities to add to the container. Conflicts
   * with option 'Capabilities'.
   */
  CapAdd?: string[];
  /**
   * A list of kernel capabilities to drop from the container. Conflicts
   * with option 'Capabilities'.
   */
  CapDrop?: string[];
  /**
   * cgroup namespace mode for the container. Possible values are:
   *
   * - `"private"`: the container runs in its own private cgroup namespace
   * - `"host"`: use the host system's cgroup namespace
   *
   * If not specified, the daemon default is used, which can either be `"private"`
   * or `"host"`, depending on daemon version, kernel support and configuration.
   */
  CgroupnsMode?: "private" | "host";
  /** A list of DNS servers for the container to use. */
  Dns?: string[];
  /** A list of DNS options. */
  DnsOptions?: string[];
  /** A list of DNS search domains. */
  DnsSearch?: string[];
  /**
   * A list of hostnames/IP mappings to add to the container's `/etc/hosts`
   * file. Specified in the form `["hostname:IP"]`.
   */
  ExtraHosts?: string[];
  /** A list of additional groups that the container process will run as. */
  GroupAdd?: string[];
  /**
   * IPC sharing mode for the container. Possible values are:
   *
   * - `"none"`: own private IPC namespace, with /dev/shm not mounted
   * - `"private"`: own private IPC namespace
   * - `"shareable"`: own private IPC namespace, with a possibility to share it with other containers
   * - `"container:<name|id>"`: join another (shareable) container's IPC namespace
   * - `"host"`: use the host system's IPC namespace
   *
   * If not specified, daemon default is used, which can either be `"private"`
   * or `"shareable"`, depending on daemon version and configuration.
   */
  IpcMode?: string;
  /** Cgroup to use for the container. */
  Cgroup?: string;
  /** A list of links for the container in the form `container_name:alias`. */
  Links?: string[];
  /**
   * An integer value containing the score given to the container in
   * order to tune OOM killer preferences.
   */
  OomScoreAdj?: int32;
  /**
   * Set the PID (Process) Namespace mode for the container. It can be
   * either:
   *
   * - `"container:<name|id>"`: joins another container's PID namespace
   * - `"host"`: use the host's PID namespace inside the container
   */
  PidMode?: string;
  /** Gives the container full access to the host. */
  Privileged?: boolean;
  /**
   * Allocates an ephemeral host port for all of a container's
   * exposed ports.
   *
   * Ports are de-allocated when the container stops and allocated when
   * the container starts. The allocated port might be changed when
   * restarting the container.
   *
   * The port is selected from the ephemeral port range that depends on
   * the kernel. For example, on Linux the range is defined by
   * `/proc/sys/net/ipv4/ip_local_port_range`.
   */
  PublishAllPorts?: boolean;
  /** Mount the container's root filesystem as read only. */
  ReadonlyRootfs?: boolean;
  /**
   * A list of string values to customize labels for MLS systems, such
   * as SELinux.
   */
  SecurityOpt?: string[];
  /** Storage driver options for this container, in the form `{"size": "120G"}`. */
  StorageOpt?: Record<string>;
  /**
   * A map of container directories which should be replaced by tmpfs
   * mounts, and their corresponding mount options. For example:
   *
   * ```
   * { "/run": "rw,noexec,nosuid,size=65536k" }
   * ```
   */
  Tmpfs?: Record<string>;
  /** UTS namespace to use for the container. */
  UTSMode?: string;
  /**
   * Sets the usernamespace mode for the container when usernamespace
   * remapping option is enabled.
   */
  UsernsMode?: string;
  /** Size of `/dev/shm` in bytes. If omitted, the system uses 64MB. */
  ShmSize?: int64;
  /**
   * A list of kernel parameters (sysctls) to set in the container.
   *
   * This field is omitted if not set.
   */
  Sysctls?: Record<string> | null;
  /** Runtime to use with this container. */
  Runtime?: string | null;
  /** Isolation technology of the container. (Windows only) */
  Isolation?: "default" | "process" | "hyperv" | "";
  /**
   * The list of paths to be masked inside the container (this overrides
   * the default set of paths).
   */
  MaskedPaths?: string[];
  /**
   * The list of paths to be set as read-only inside the container
   * (this overrides the default set of paths).
   */
  ReadonlyPaths?: string[];
}

/** A container's resources (cgroups config, ulimits, etc) */
model Resources {
  /**
   * An integer value representing this container's relative CPU weight
   * versus other containers.
   */
  CpuShares?: int32;
  /** Memory limit in bytes. */
  Memory?: int64;
  /**
   * Path to `cgroups` under which the container's `cgroup` is created. If
   * the path is not absolute, the path is considered to be relative to the
   * `cgroups` path of the init process. Cgroups are created if they do not
   * already exist.
   */
  CgroupParent?: string;
  /** Block IO weight (relative weight). */
  BlkioWeight?: int32;
  /**
   * Block IO weight (relative device weight) in the form:
   *
   * ```
   * [{"Path": "device_path", "Weight": weight}]
   * ```
   */
  BlkioWeightDevice?: {
    Path?: string;
    Weight?: int32;
  }[];
  /**
   * Limit read rate (bytes per second) from a device, in the form:
   *
   * ```
   * [{"Path": "device_path", "Rate": rate}]
   * ```
   */
  BlkioDeviceReadBps?: ThrottleDevice[];
  /**
   * Limit write rate (bytes per second) to a device, in the form:
   *
   * ```
   * [{"Path": "device_path", "Rate": rate}]
   * ```
   */
  BlkioDeviceWriteBps?: ThrottleDevice[];
  /**
   * Limit read rate (IO per second) from a device, in the form:
   *
   * ```
   * [{"Path": "device_path", "Rate": rate}]
   * ```
   */
  BlkioDeviceReadIOps?: ThrottleDevice[];
  /**
   * Limit write rate (IO per second) to a device, in the form:
   *
   * ```
   * [{"Path": "device_path", "Rate": rate}]
   * ```
   */
  BlkioDeviceWriteIOps?: ThrottleDevice[];
  /** The length of a CPU period in microseconds. */
  CpuPeriod?: int64;
  /** Microseconds of CPU time that the container can get in a CPU period. */
  CpuQuota?: int64;
  /**
   * The length of a CPU real-time period in microseconds. Set to 0 to
   * allocate no time allocated to real-time tasks.
   */
  CpuRealtimePeriod?: int64;
  /**
   * The length of a CPU real-time runtime in microseconds. Set to 0 to
   * allocate no time allocated to real-time tasks.
   */
  CpuRealtimeRuntime?: int64;
  /** CPUs in which to allow execution (e.g., `0-3`, `0,1`). */
  CpusetCpus?: string;
  /**
   * Memory nodes (MEMs) in which to allow execution (0-3, 0,1). Only
   * effective on NUMA systems.
   */
  CpusetMems?: string;
  /** A list of devices to add to the container. */
  Devices?: DeviceMapping[];
  /** a list of cgroup rules to apply to the container */
  DeviceCgroupRules?: string[];
  /** A list of requests for devices to be sent to device drivers. */
  DeviceRequests?: DeviceRequest[];
  /** Memory soft limit in bytes. */
  MemoryReservation?: int64;
  /**
   * Total memory limit (memory + swap). Set as `-1` to enable unlimited
   * swap.
   */
  MemorySwap?: int64;
  /**
   * Tune a container's memory swappiness behavior. Accepts an integer
   * between 0 and 100.
   */
  MemorySwappiness?: int64;
  /** CPU quota in units of 10<sup>-9</sup> CPUs. */
  NanoCpus?: int64;
  /** Disable OOM Killer for the container. */
  OomKillDisable?: boolean;
  /**
   * Run an init inside the container that forwards signals and reaps
   * processes. This field is omitted if empty, and the default (as
   * configured on the daemon) is used.
   */
  `Init`?: boolean | null;
  /**
   * Tune a container's PIDs limit. Set `0` or `-1` for unlimited, or `null`
   * to not change.
   */
  PidsLimit?: int64 | null;
  /**
   * A list of resource limits to set in the container. For example:
   *
   * ```
   * {"Name": "nofile", "Soft": 1024, "Hard": 2048}
   * ```
   */
  Ulimits?: {
    Name?: string;
    Soft?: int32;
    Hard?: int32;
  }[];
  /**
   * The number of usable CPUs (Windows only).
   *
   * On Windows Server containers, the processor resource controls are
   * mutually exclusive. The order of precedence is `CPUCount` first, then
   * `CPUShares`, and `CPUPercent` last.
   */
  CpuCount?: int64;
  /**
   * The usable percentage of the available CPUs (Windows only).
   *
   * On Windows Server containers, the processor resource controls are
   * mutually exclusive. The order of precedence is `CPUCount` first, then
   * `CPUShares`, and `CPUPercent` last.
   */
  CpuPercent?: int64;
  /** Maximum IOps for the container system drive (Windows only) */
  IOMaximumIOps?: int64;
  /**
   * Maximum IO in bytes per second for the container system drive
   * (Windows only).
   */
  IOMaximumBandwidth?: int64;
}

/**
 * The behavior to apply when the container exits. The default is not to
 * restart.
 *
 * An ever increasing delay (double the previous delay, starting at 100ms) is
 * added before each restart to prevent flooding the server.
 */
model RestartPolicy {
  /**
   * - Empty string means not to restart
   * - `no` Do not automatically restart
   * - `always` Always restart
   * - `unless-stopped` Restart always except when the user has manually stopped the container
   * - `on-failure` Restart only when the container exit code is non-zero
   */
  Name?: "" | "no" | "always" | "unless-stopped" | "on-failure";
  /** If `on-failure` is used, the number of times to retry before giving up. */
  MaximumRetryCount?: int32;
}

/**
 * A test to perform to check that the container is healthy.
 * Healthcheck commands should be side-effect free.
 */
model HealthConfig {
  /**
   * The test to perform. Possible values are:
   *
   * - `[]` inherit healthcheck from image or parent image
   * - `["NONE"]` disable healthcheck
   * - `["CMD", args...]` exec arguments directly
   * - `["CMD-SHELL", command]` run command with system's default shell
   *
   * A non-zero exit code indicates a failed healthcheck:
   * - `0` healthy
   * - `1` unhealthy
   * - `2` reserved (treated as unhealthy)
   * - other values: error running probe
   */
  Test?: string[];
  /**
   * The time to wait between checks in nanoseconds. It should be 0 or at
   * least 1000000 (1 ms). 0 means inherit.
   */
  Interval?: int64;
  /**
   * The time to wait before considering the check to have hung. It should
   * be 0 or at least 1000000 (1 ms). 0 means inherit.
   *
   * If the health check command does not complete within this timeout,
   * the check is considered failed and the health check process is
   * forcibly terminated without a graceful shutdown.
   */
  Timeout?: int64;
  /**
   * The number of consecutive failures needed to consider a container as
   * unhealthy. 0 means inherit.
   */
  Retries?: int32;
  /**
   * Start period for the container to initialize before starting
   * health-retries countdown in nanoseconds. It should be 0 or at least
   * 1000000 (1 ms). 0 means inherit.
   */
  StartPeriod?: int64;
  /**
   * The time to wait between checks in nanoseconds during the start period.
   * It should be 0 or at least 1000000 (1 ms). 0 means inherit.
   */
  StartInterval?: int64;
}

/** Health stores information about the container's healthcheck results. */
model Health {
  /**
   * Status is one of `none`, `starting`, `healthy` or `unhealthy`
   *
   * - "none"      Indicates there is no healthcheck
   * - "starting"  Starting indicates that the container is not yet ready
   * - "healthy"   Healthy indicates that the container is running correctly
   * - "unhealthy" Unhealthy indicates that the container has a problem
   */
  Status?: "none" | "starting" | "healthy" | "unhealthy";
  /** FailingStreak is the number of consecutive failures */
  FailingStreak?: int32;
  /** Log contains the last few results (oldest first) */
  Log?: HealthcheckResult[];
}

/** HealthcheckResult stores information about a single run of a healthcheck probe */
model HealthcheckResult {
  /**
   * Date and time at which this check started in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  Start?: utcDateTime;
  /**
   * Date and time at which this check ended in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  End?: utcDateTime;
  /**
   * ExitCode meanings:
   *
   * - `0` healthy
   * - `1` unhealthy
   * - `2` reserved (considered unhealthy)
   * - other values: error running probe
   */
  ExitCode?: int32;
  /** Output from last check */
  Output?: string;
}

/**
 * NetworkingConfig represents the container's networking configuration for
 * each of its interfaces.
 * It is used for the networking configs specified in the `docker create`
 * and `docker network connect` commands.
 */
model NetworkingConfig {
  /**
   * A mapping of network name to endpoint configuration for that network.
   * The endpoint configuration can be left empty to connect to that
   * network with no particular endpoint configuration.
   */
  EndpointsConfig?: Record<EndpointSettings>;
}

/** NetworkSettings exposes the network settings in the API */
model NetworkSettings {
  /** SandboxID uniquely represents a container's network stack. */
  SandboxID?: string;
  /** SandboxKey is the full path of the netns handle */
  SandboxKey?: string;
  Ports?: PortMap;
  /** Information about all networks that the container is connected to. */
  Networks?: Record<EndpointSettings>;
}

model ContainerInspectResponse {
  /**
   * The ID of this container as a 128-bit (64-character) hexadecimal string (32 bytes).
   */
  Id?: string;
  /**
   * Date and time at which the container was created, formatted in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  Created?: utcDateTime | null;
  /** The path to the command being run */
  Path?: string;
  /** The arguments to the command being run */
  Args?: string[];
  State?: ContainerState;
  /** The ID (digest) of the image that this container was created from. */
  Image?: string;
  /**
   * Location of the `/etc/resolv.conf` generated for the container on the
   * host.
   *
   * This file is managed through the docker daemon, and should not be
   * accessed or modified by other tools.
   */
  ResolvConfPath?: string;
  /**
   * Location of the `/etc/hostname` generated for the container on the
   * host.
   *
   * This file is managed through the docker daemon, and should not be
   * accessed or modified by other tools.
   */
  HostnamePath?: string;
  /**
   * Location of the `/etc/hosts` generated for the container on the
   * host.
   *
   * This file is managed through the docker daemon, and should not be
   * accessed or modified by other tools.
   */
  HostsPath?: string;
  /**
   * Location of the file used to buffer the container's logs. Depending on
   * the logging-driver used for the container, this field may be omitted.
   *
   * This file is managed through the docker daemon, and should not be
   * accessed or modified by other tools.
   */
  LogPath?: string | null;
  /**
   * The name associated with this container.
   *
   * For historic reasons, the name may be prefixed with a forward-slash (`/`).
   */
  Name?: string;
  /**
   * Number of times the container was restarted since it was created,
   * or since daemon was started.
   */
  RestartCount?: int32;
  /**
   * The storage-driver used for the container's filesystem (graph-driver
   * or snapshotter).
   */
  Driver?: string;
  /**
   * The platform (operating system) for which the container was created.
   *
   * This field was introduced for the experimental "LCOW" (Linux Containers
   * On Windows) features, which has been removed. In most cases, this field
   * is equal to the host's operating system (`linux` or `windows`).
   */
  Platform?: string;
  /**
   * OCI descriptor of the platform-specific manifest of the image
   * the container was created from.
   *
   * Note: Only available if the daemon provides a multi-platform
   * image store.
   */
  ImageManifestDescriptor?: OCIDescriptor;
  /** SELinux mount label set for the container. */
  MountLabel?: string;
  /** SELinux process label set for the container. */
  ProcessLabel?: string;
  /** The AppArmor profile set for the container. */
  AppArmorProfile?: string;
  /** IDs of exec instances that are running in the container. */
  ExecIDs?: string[] | null;
  HostConfig?: HostConfig;
  GraphDriver?: DriverData | null;
  Storage?: Storage | null;
  /**
   * The size of files that have been created or changed by this container.
   *
   * This field is omitted by default, and only set when size is requested
   * in the API request.
   */
  SizeRw?: int64 | null;
  /**
   * The total size of all files in the read-only layers from the image
   * that the container uses. These layers can be shared between containers.
   *
   * This field is omitted by default, and only set when size is requested
   * in the API request.
   */
  SizeRootFs?: int64 | null;
  /** List of mounts used by the container. */
  Mounts?: MountPoint[];
  Config?: ContainerConfig;
  NetworkSettings?: NetworkSettings;
}

model ContainerSummary {
  /**
   * The ID of this container as a 128-bit (64-character) hexadecimal string (32 bytes).
   */
  Id?: string;
  /**
   * The names associated with this container. Most containers have a single
   * name, but when using legacy "links", the container can have multiple
   * names.
   *
   * For historic reasons, names are prefixed with a forward-slash (`/`).
   */
  Names?: string[];
  /**
   * The name or ID of the image used to create the container.
   *
   * This field shows the image reference as was specified when creating the container,
   * which can be in its canonical form (e.g., `docker.io/library/ubuntu:latest`
   * or `docker.io/library/ubuntu@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782`),
   * short form (e.g., `ubuntu:latest`)), or the ID(-prefix) of the image (e.g., `72297848456d`).
   *
   * The content of this field can be updated at runtime if the image used to
   * create the container is untagged, in which case the field is updated to
   * contain the the image ID (digest) it was resolved to in its canonical,
   * non-truncated form (e.g., `sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782`).
   */
  Image?: string;
  /** The ID (digest) of the image that this container was created from. */
  ImageID?: string;
  /**
   * OCI descriptor of the platform-specific manifest of the image
   * the container was created from.
   *
   * Note: Only available if the daemon provides a multi-platform
   * image store.
   *
   * This field is not populated in the `GET /system/df` endpoint.
   */
  ImageManifestDescriptor?: OCIDescriptor | null;
  /** Command to run when starting the container */
  Command?: string;
  /**
   * Date and time at which the container was created as a Unix timestamp
   * (number of seconds since EPOCH).
   */
  Created?: int64;
  /** Port-mappings for the container. */
  Ports?: PortSummary[];
  /**
   * The size of files that have been created or changed by this container.
   *
   * This field is omitted by default, and only set when size is requested
   * in the API request.
   */
  SizeRw?: int64 | null;
  /**
   * The total size of all files in the read-only layers from the image
   * that the container uses. These layers can be shared between containers.
   *
   * This field is omitted by default, and only set when size is requested
   * in the API request.
   */
  SizeRootFs?: int64 | null;
  /** User-defined key/value metadata. */
  Labels?: Record<string>;
  /** The state of this container. */
  State?: "created" | "running" | "paused" | "restarting" | "exited" | "removing" | "dead";
  /** Additional human-readable status of this container (e.g. `Exit 0`) */
  Status?: string;
  /**
   * Summary of host-specific runtime information of the container. This
   * is a reduced set of information in the container's "HostConfig" as
   * available in the container "inspect" response.
   */
  HostConfig?: {
    NetworkMode?: string;
    Annotations?: Record<string> | null;
  };
  /** Summary of the container's network settings */
  NetworkSettings?: {
    Networks?: Record<EndpointSettings>;
  };
  /** List of mounts used by the container. */
  Mounts?: MountPoint[];
  /**
   * Summary of health status
   *
   * Added in v1.52, before that version all container summary not include Health.
   * After this attribute introduced, it includes containers with no health checks configured,
   * or containers that are not running with none
   */
  Health?: {
    Status?: "none" | "starting" | "healthy" | "unhealthy";
    FailingStreak?: int32;
  };
}

/**
 * ContainerState stores container's running state. It's part of ContainerJSONBase
 * and will be returned by the "inspect" command.
 */
model ContainerState {
  /**
   * String representation of the container state. Can be one of "created",
   * "running", "paused", "restarting", "removing", "exited", or "dead".
   */
  Status?: "created" | "running" | "paused" | "restarting" | "removing" | "exited" | "dead";
  /**
   * Whether this container is running.
   *
   * Note that a running container can be _paused_. The `Running` and `Paused`
   * booleans are not mutually exclusive:
   *
   * When pausing a container (on Linux), the freezer cgroup is used to suspend
   * all processes in the container. Freezing the process requires the process to
   * be running. As a result, paused containers are both `Running` _and_ `Paused`.
   *
   * Use the `Status` field instead to determine if a container's state is "running".
   */
  Running?: boolean;
  /** Whether this container is paused. */
  Paused?: boolean;
  /** Whether this container is restarting. */
  Restarting?: boolean;
  /**
   * Whether a process within this container has been killed because it ran
   * out of memory since the container was last started.
   */
  OOMKilled?: boolean;
  Dead?: boolean;
  /** The process ID of this container */
  Pid?: int32;
  /** The last exit code of this container */
  ExitCode?: int32;
  Error?: string;
  /** The time when this container was last started. */
  StartedAt?: string;
  /** The time when this container last exited. */
  FinishedAt?: string;
  Health?: Health;
}

/** OK response to ContainerCreate operation */
model ContainerCreateResponse {
  /** The ID of the created container */
  Id: string;
  /** Warnings encountered when creating the container */
  Warnings: string[];
}

/** Response for a successful container-update. */
model ContainerUpdateResponse {
  /** Warnings encountered when updating the container. */
  Warnings?: string[];
}

/** Statistics sample for a container. */
model ContainerStatsResponse {
  /** ID of the container for which the stats were collected. */
  id?: string | null;
  /** Name of the container for which the stats were collected. */
  name?: string | null;
  /**
   * OSType is the OS of the container ("linux" or "windows") to allow
   * platform-specific handling of stats.
   */
  os_type?: string | null;
  /**
   * Date and time at which this sample was collected.
   * The value is formatted as [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt)
   * with nano-seconds.
   */
  read?: utcDateTime;
  cpu_stats?: ContainerCPUStats;
  memory_stats?: ContainerMemoryStats;
  /**
   * Network statistics for the container per interface.
   *
   * This field is omitted if the container has no networking enabled.
   */
  networks?: Record<ContainerNetworkStats> | null;
  pids_stats?: ContainerPidsStats;
  blkio_stats?: ContainerBlkioStats;
  /**
   * The number of processors on the system.
   *
   * This field is Windows-specific and always zero for Linux containers.
   */
  num_procs?: uint32;
  storage_stats?: ContainerStorageStats;
  /**
   * Date and time at which this first sample was collected. This field
   * is not propagated if the "one-shot" option is set. If the "one-shot"
   * option is set, this field may be omitted, empty, or set to a default
   * date (`0001-01-01T00:00:00Z`).
   *
   * The value is formatted as [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt)
   * with nano-seconds.
   */
  preread?: utcDateTime;
  precpu_stats?: ContainerCPUStats;
}

/**
 * BlkioStats stores all IO service stats for data read and write.
 *
 * This type is Linux-specific and holds many fields that are specific to cgroups v1.
 * On a cgroup v2 host, all fields other than `io_service_bytes_recursive`
 * are omitted or `null`.
 *
 * This type is only populated on Linux and omitted for Windows containers.
 */
model ContainerBlkioStats {
  io_service_bytes_recursive?: ContainerBlkioStatEntry[];
  /**
   * This field is only available when using Linux containers with
   * cgroups v1. It is omitted or `null` when using cgroups v2.
   */
  io_serviced_recursive?: ContainerBlkioStatEntry[] | null;
  /**
   * This field is only available when using Linux containers with
   * cgroups v1. It is omitted or `null` when using cgroups v2.
   */
  io_queue_recursive?: ContainerBlkioStatEntry[] | null;
  /**
   * This field is only available when using Linux containers with
   * cgroups v1. It is omitted or `null` when using cgroups v2.
   */
  io_service_time_recursive?: ContainerBlkioStatEntry[] | null;
  /**
   * This field is only available when using Linux containers with
   * cgroups v1. It is omitted or `null` when using cgroups v2.
   */
  io_wait_time_recursive?: ContainerBlkioStatEntry[] | null;
  /**
   * This field is only available when using Linux containers with
   * cgroups v1. It is omitted or `null` when using cgroups v2.
   */
  io_merged_recursive?: ContainerBlkioStatEntry[] | null;
  /**
   * This field is only available when using Linux containers with
   * cgroups v1. It is omitted or `null` when using cgroups v2.
   */
  io_time_recursive?: ContainerBlkioStatEntry[] | null;
  /**
   * This field is only available when using Linux containers with
   * cgroups v1. It is omitted or `null` when using cgroups v2.
   */
  sectors_recursive?: ContainerBlkioStatEntry[] | null;
}

/**
 * Blkio stats entry.
 *
 * This type is Linux-specific and omitted for Windows containers.
 */
model ContainerBlkioStatEntry {
  major?: uint64;
  minor?: uint64;
  `op`?: string;
  value?: uint64;
}

/** CPU related info of the container */
model ContainerCPUStats {
  cpu_usage?: ContainerCPUUsage;
  /**
   * System Usage.
   *
   * This field is Linux-specific and omitted for Windows containers.
   */
  system_cpu_usage?: uint64 | null;
  /**
   * Number of online CPUs.
   *
   * This field is Linux-specific and omitted for Windows containers.
   */
  online_cpus?: uint32 | null;
  throttling_data?: ContainerThrottlingData;
}

/** All CPU stats aggregated since container inception. */
model ContainerCPUUsage {
  /**
   * Total CPU time consumed in nanoseconds (Linux) or 100's of nanoseconds (Windows).
   */
  total_usage?: uint64;
  /**
   * Total CPU time (in nanoseconds) consumed per core (Linux).
   *
   * This field is Linux-specific when using cgroups v1. It is omitted
   * when using cgroups v2 and Windows containers.
   */
  percpu_usage?: uint64[] | null;
  /**
   * Time (in nanoseconds) spent by tasks of the cgroup in kernel mode (Linux),
   * or time spent (in 100's of nanoseconds) by all container processes in
   * kernel mode (Windows).
   *
   * Not populated for Windows containers using Hyper-V isolation.
   */
  usage_in_kernelmode?: uint64;
  /**
   * Time (in nanoseconds) spent by tasks of the cgroup in user mode (Linux),
   * or time spent (in 100's of nanoseconds) by all container processes in
   * kernel mode (Windows).
   *
   * Not populated for Windows containers using Hyper-V isolation.
   */
  usage_in_usermode?: uint64;
}

/**
 * PidsStats contains Linux-specific stats of a container's process-IDs (PIDs).
 *
 * This type is Linux-specific and omitted for Windows containers.
 */
model ContainerPidsStats {
  /** Current is the number of PIDs in the cgroup. */
  current?: uint64 | null;
  /**
   * Limit is the hard limit on the number of pids in the cgroup.
   * A "Limit" of 0 means that there is no limit.
   */
  limit?: uint64 | null;
}

/**
 * CPU throttling stats of the container.
 *
 * This type is Linux-specific and omitted for Windows containers.
 */
model ContainerThrottlingData {
  /** Number of periods with throttling active. */
  periods?: uint64;
  /** Number of periods when the container hit its throttling limit. */
  throttled_periods?: uint64;
  /** Aggregated time (in nanoseconds) the container was throttled for. */
  throttled_time?: uint64;
}

/**
 * Aggregates all memory stats since container inception on Linux.
 * Windows returns stats for commit and private working set only.
 */
model ContainerMemoryStats {
  /**
   * Current `res_counter` usage for memory.
   *
   * This field is Linux-specific and omitted for Windows containers.
   */
  usage?: uint64 | null;
  /**
   * Maximum usage ever recorded.
   *
   * This field is Linux-specific and only supported on cgroups v1.
   * It is omitted when using cgroups v2 and for Windows containers.
   */
  max_usage?: uint64 | null;
  /**
   * All the stats exported via memory.stat.
   *
   * The fields in this object differ between cgroups v1 and v2.
   * On cgroups v1, fields such as `cache`, `rss`, `mapped_file` are available.
   * On cgroups v2, fields such as `file`, `anon`, `inactive_file` are available.
   *
   * This field is Linux-specific and omitted for Windows containers.
   */
  stats?: Record<uint64>;
  /**
   * Number of times memory usage hits limits.
   *
   * This field is Linux-specific and only supported on cgroups v1.
   * It is omitted when using cgroups v2 and for Windows containers.
   */
  failcnt?: uint64 | null;
  /** This field is Linux-specific and omitted for Windows containers. */
  limit?: uint64 | null;
  /**
   * Committed bytes.
   *
   * This field is Windows-specific and omitted for Linux containers.
   */
  commitbytes?: uint64 | null;
  /**
   * Peak committed bytes.
   *
   * This field is Windows-specific and omitted for Linux containers.
   */
  commitpeakbytes?: uint64 | null;
  /**
   * Private working set.
   *
   * This field is Windows-specific and omitted for Linux containers.
   */
  privateworkingset?: uint64 | null;
}

/** Aggregates the network stats of one container */
model ContainerNetworkStats {
  /** Bytes received. Windows and Linux. */
  rx_bytes?: uint64;
  /** Packets received. Windows and Linux. */
  rx_packets?: uint64;
  /**
   * Received errors. Not used on Windows.
   *
   * This field is Linux-specific and always zero for Windows containers.
   */
  rx_errors?: uint64;
  /** Incoming packets dropped. Windows and Linux. */
  rx_dropped?: uint64;
  /** Bytes sent. Windows and Linux. */
  tx_bytes?: uint64;
  /** Packets sent. Windows and Linux. */
  tx_packets?: uint64;
  /**
   * Sent errors. Not used on Windows.
   *
   * This field is Linux-specific and always zero for Windows containers.
   */
  tx_errors?: uint64;
  /** Outgoing packets dropped. Windows and Linux. */
  tx_dropped?: uint64;
  /**
   * Endpoint ID. Not used on Linux.
   *
   * This field is Windows-specific and omitted for Linux containers.
   */
  endpoint_id?: string | null;
  /**
   * Instance ID. Not used on Linux.
   *
   * This field is Windows-specific and omitted for Linux containers.
   */
  instance_id?: string | null;
}

/**
 * StorageStats is the disk I/O stats for read/write on Windows.
 *
 * This type is Windows-specific and omitted for Linux containers.
 */
model ContainerStorageStats {
  read_count_normalized?: uint64 | null;
  read_size_bytes?: uint64 | null;
  write_count_normalized?: uint64 | null;
  write_size_bytes?: uint64 | null;
}

/** Container "top" response. */
model ContainerTopResponse {
  /** The ps column titles */
  Titles?: string[];
  /**
   * Each process running in the container, where each process
   * is an array of values corresponding to the titles.
   */
  Processes?: string[][];
}

/** OK response to ContainerWait operation */
model ContainerWaitResponse {
  /** Exit code of the container */
  StatusCode: int64;
  Error?: ContainerWaitExitError;
}

/** container waiting error, if any */
model ContainerWaitExitError {
  /** Details of an error */
  Message?: string;
}

/** Change in the container's filesystem. */
model FilesystemChange {
  /** Path to file or directory that has changed. */
  Path: string;
  Kind: ChangeType;
}

/**
 * Kind of change
 *
 * Can be one of:
 *
 * - `0`: Modified ("C")
 * - `1`: Added ("A")
 * - `2`: Deleted ("D")
 */
union ChangeType {
  0,
  1,
  2,
}

/** represents system data usage information for container resources. */
model ContainersDiskUsage {
  /** Count of active containers. */
  ActiveCount?: int64;
  /** Count of all containers. */
  TotalCount?: int64;
  /** Disk space that can be reclaimed by removing inactive containers. */
  Reclaimable?: int64;
  /** Disk space in use by containers. */
  TotalSize?: int64;
  /** List of container summaries. */
  Items?: unknown[];
}

/** represents the status of a container. */
model ContainerStatus {
  ContainerID?: string;
  PID?: int32;
  ExitCode?: int32;
}

/** An object describing a limit on resources which can be requested by a task. */
model Limit {
  NanoCPUs?: int64;
  MemoryBytes?: int64;
  /** Limits the maximum number of PIDs in the container. Set `0` for unlimited. */
  Pids?: int64;
}

/**
 * An object describing the resources which can be advertised by a node and
 * requested by a task.
 */
model ResourceObject {
  NanoCPUs?: int64;
  MemoryBytes?: int64;
  GenericResources?: GenericResources;
}

/**
 * User-defined resources can be either Integer resources (e.g, `SSD=3`) or
 * String resources (e.g, `GPU=UUID1`).
 */
alias GenericResources = {
  NamedResourceSpec?: {
    Kind?: string;
    Value?: string;
  };
  DiscreteResourceSpec?: {
    Kind?: string;
    Value?: int64;
  };
}[];
