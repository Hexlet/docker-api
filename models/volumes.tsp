import "@typespec/http";
import "@typespec/openapi";

import "./common.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

model Volume {
  /** Name of the volume. */
  Name: string;
  /** Name of the volume driver used by the volume. */
  Driver: string;
  /** Mount path of the volume on the host. */
  Mountpoint: string;
  /** Date/Time the volume was created. */
  CreatedAt?: utcDateTime;
  /**
   * Low-level details about the volume, provided by the volume driver.
   * Details are returned as a map with key/value pairs:
   * `{"key":"value","key2":"value2"}`.
   *
   * The `Status` field is optional, and is omitted if the volume driver
   * does not support this feature.
   */
  Status?: Record<Record<unknown>>;
  /** User-defined key/value metadata. */
  Labels: Record<string>;
  /**
   * The level at which the volume exists. Either `global` for cluster-wide,
   * or `local` for machine level.
   */
  Scope: "local" | "global";
  ClusterVolume?: ClusterVolume;
  /** The driver specific options used when creating the volume. */
  Options: Record<string>;
  /**
   * Usage details about the volume. This information is used by the
   * `GET /system/df` endpoint, and omitted in other endpoints.
   */
  UsageData?: {
    Size: int64;
    RefCount: int64;
  } | null;
}

/** Volume configuration */
model VolumeCreateRequest {
  /** The new volume's name. If not specified, Docker generates a name. */
  Name?: string;
  /** Name of the volume driver to use. */
  Driver?: string;
  /**
   * A mapping of driver options and values. These options are
   * passed directly to the driver and are driver specific.
   */
  DriverOpts?: Record<string>;
  /** User-defined key/value metadata. */
  Labels?: Record<string>;
  ClusterVolumeSpec?: ClusterVolumeSpec;
}

/** Volume list response */
model VolumeListResponse {
  /** List of volumes */
  Volumes?: Volume[];
  /** Warnings that occurred when fetching the list of volumes. */
  Warnings?: string[];
}

/** represents system data usage for volume resources. */
model VolumesDiskUsage {
  /** Count of active volumes. */
  ActiveCount?: int64;
  /** Count of all volumes. */
  TotalCount?: int64;
  /** Disk space that can be reclaimed by removing inactive volumes. */
  Reclaimable?: int64;
  /** Disk space in use by volumes. */
  TotalSize?: int64;
  /** List of volumes. */
  Items?: unknown[];
}

/**
 * Options and information specific to, and only present on, Swarm CSI
 * cluster volumes.
 */
model ClusterVolume {
  /**
   * The Swarm ID of this volume. Because cluster volumes are Swarm
   * objects, they have an ID, unlike non-cluster volumes. This ID can
   * be used to refer to the Volume instead of the name.
   */
  ID?: string;
  Version?: ObjectVersion;
  CreatedAt?: utcDateTime;
  UpdatedAt?: utcDateTime;
  Spec?: ClusterVolumeSpec;
  /** Information about the global status of the volume. */
  Info?: {
    CapacityBytes?: int64;
    VolumeContext?: Record<string>;
    VolumeID?: string;
    AccessibleTopology?: Topology[];
  };
  /**
   * The status of the volume as it pertains to its publishing and use on
   * specific nodes
   */
  PublishStatus?: ({
    NodeID?: string;
    State?: "pending-publish" | "published" | "pending-node-unpublish" | "pending-controller-unpublish";
    PublishContext?: Record<string>;
  })[];
}

/** Cluster-specific options used to create the volume. */
model ClusterVolumeSpec {
  /**
   * Group defines the volume group of this volume. Volumes belonging to
   * the same group can be referred to by group name when creating
   * Services.  Referring to a volume by group instructs Swarm to treat
   * volumes in that group interchangeably for the purpose of scheduling.
   * Volumes with an empty string for a group technically all belong to
   * the same, emptystring group.
   */
  Group?: string;
  /** Defines how the volume is used by tasks. */
  AccessMode?: {
    Scope?: "single" | "multi";
    Sharing?: "none" | "readonly" | "onewriter" | "all";
    MountVolume?: Record<unknown>;
    Secrets?: {
      Key?: string;
      Secret?: string;
    }[];
    AccessibilityRequirements?: {
      Requisite?: Topology[];
      Preferred?: Topology[];
    };
    CapacityRange?: {
      RequiredBytes?: int64;
      LimitBytes?: int64;
    };
    Availability?: "active" | "pause" | "drain";
  };
}

/**
 * A map of topological domains to topological segments. For in depth
 * details, see documentation for the Topology object in the CSI
 * specification.
 */
alias Topology = Record<string>;

/**
 * Information about the storage driver used to store the container's and
 * image's filesystem.
 */
model DriverData {
  /** Name of the storage driver. */
  Name: string;
  /**
   * Low-level storage metadata, provided as key/value pairs.
   *
   * This information is driver-specific, and depends on the storage-driver
   * in use, and should be used for informational purposes only.
   */
  Data: Record<string>;
}
