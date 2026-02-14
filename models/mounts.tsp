import "@typespec/http";
import "@typespec/openapi";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/**
 * The mount type. Available types:
 *
 * - `bind` a mount of a file or directory from the host into the container.
 * - `cluster` a Swarm cluster volume.
 * - `image` an OCI image.
 * - `npipe` a named pipe from the host into the container.
 * - `tmpfs` a `tmpfs`.
 * - `volume` a docker volume with the given `Name`.
 */
union MountType {
  "bind",
  "cluster",
  "image",
  "npipe",
  "tmpfs",
  "volume",
}

/**
 * MountPoint represents a mount point configuration inside the container.
 * This is used for reporting the mountpoints in use by a container.
 */
model MountPoint {
  /**
   * The mount type:
   *
   * - `bind` a mount of a file or directory from the host into the container.
   * - `cluster` a Swarm cluster volume.
   * - `image` an OCI image.
   * - `npipe` a named pipe from the host into the container.
   * - `tmpfs` a `tmpfs`.
   * - `volume` a docker volume with the given `Name`.
   */
  Type?: MountType;
  /**
   * Name is the name reference to the underlying data defined by `Source`
   * e.g., the volume name.
   */
  Name?: string;
  /**
   * Source location of the mount.
   *
   * For volumes, this contains the storage location of the volume (within
   * `/var/lib/docker/volumes/`). For bind-mounts, and `npipe`, this contains
   * the source (host) part of the bind-mount. For `tmpfs` mount points, this
   * field is empty.
   */
  Source?: string;
  /**
   * Destination is the path relative to the container root (`/`) where
   * the `Source` is mounted inside the container.
   */
  Destination?: string;
  /** Driver is the volume driver used to create the volume (if it is a volume). */
  Driver?: string;
  /**
   * Mode is a comma separated list of options supplied by the user when
   * creating the bind/volume mount.
   *
   * The default is platform-specific (`"z"` on Linux, empty on Windows).
   */
  Mode?: string;
  /** Whether the mount is mounted writable (read-write). */
  RW?: boolean;
  /**
   * Propagation describes how mounts are propagated from the host into the
   * mount point, and vice-versa. Refer to the [Linux kernel documentation](https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt)
   * for details. This field is not used on Windows.
   */
  Propagation?: string;
}

/** A device mapping between the host and container */
model DeviceMapping {
  PathOnHost?: string;
  PathInContainer?: string;
  CgroupPermissions?: string;
}

/** A request for devices to be sent to device drivers */
model DeviceRequest {
  /**
   * The name of the device driver to use for this request.
   *
   * Note that if this is specified the capabilities are ignored when
   * selecting a device driver.
   */
  Driver?: string;
  Count?: int32;
  DeviceIDs?: string[];
  /**
   * A list of capabilities; an OR list of AND lists of capabilities.
   *
   * Note that if a driver is specified the capabilities have no effect on
   * selecting a driver as the driver name is used directly.
   *
   * Note that if no driver is specified the capabilities are used to
   * select a driver with the required capabilities.
   */
  Capabilities?: string[][];
  /**
   * Driver-specific options, specified as a key/value pairs. These options
   * are passed directly to the driver.
   */
  Options?: Record<string>;
}

model ThrottleDevice {
  /** Device path */
  Path?: string;
  /** Rate */
  Rate?: int64;
}

model Mount {
  /** Container path. */
  Target?: string;
  /**
   * Mount source (e.g. a volume name, a host path). The source cannot be
   * specified when using `Type=tmpfs`. For `Type=bind`, the source path
   * must either exist, or the `CreateMountpoint` must be set to `true` to
   * create the source path on the host if missing.
   *
   * For `Type=npipe`, the pipe must exist prior to creating the container.
   */
  Source?: string;
  /**
   * The mount type. Available types:
   *
   * - `bind` Mounts a file or directory from the host into the container. The `Source` must exist prior to creating the container.
   * - `cluster` a Swarm cluster volume
   * - `image` Mounts an image.
   * - `npipe` Mounts a named pipe from the host into the container. The `Source` must exist prior to creating the container.
   * - `tmpfs` Create a tmpfs with the given options. The mount `Source` cannot be specified for tmpfs.
   * - `volume` Creates a volume with the given name and options (or uses a pre-existing volume with the same name and options). These are **not** removed when the container is removed.
   */
  Type?: MountType;
  /** Whether the mount should be read-only. */
  ReadOnly?: boolean;
  /**
   * The consistency requirement for the mount: `default`, `consistent`, `cached`, or `delegated`.
   */
  Consistency?: string;
  /** Optional configuration for the `bind` type. */
  BindOptions?: {
    Propagation?: "private" | "rprivate" | "shared" | "rshared" | "slave" | "rslave";
    NonRecursive?: boolean;
    CreateMountpoint?: boolean;
    ReadOnlyNonRecursive?: boolean;
    ReadOnlyForceRecursive?: boolean;
  };
  /** Optional configuration for the `volume` type. */
  VolumeOptions?: {
    NoCopy?: boolean;
    Labels?: Record<string>;
    DriverConfig?: {
      Name?: string;
      Options?: Record<string>;
    };
    Subpath?: string;
  };
  /** Optional configuration for the `image` type. */
  ImageOptions?: {
    Subpath?: string;
  };
  /** Optional configuration for the `tmpfs` type. */
  TmpfsOptions?: {
    SizeBytes?: int64;
    Mode?: int32;
    Options?: string[][];
  };
}
