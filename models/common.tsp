import "@typespec/http";
import "@typespec/openapi";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** Represents an error. */
model ErrorResponse {
  /** The error message. */
  message: string;
}

/** Response to an API call that returns just an Id */
model IDResponse {
  /** The id of the newly created object. */
  Id: string;
}

/** Driver represents a driver (network, logging, secrets). */
model Driver {
  /** Name of the driver. */
  Name: string;
  /** Key/value map of driver-specific options. */
  Options?: Record<string>;
}

/**
 * The version number of the object such as node, service, etc. This is needed
 * to avoid conflicting writes. The client must send the version number along
 * with the modified specification when updating these objects.
 *
 * This approach ensures safe concurrency and determinism in that the change
 * on the object may not be applied if the version number has changed from the
 * last read. In other words, if two update requests specify the same base
 * version, only one of the requests can succeed. As a result, two separate
 * update requests that happen at the same time will not unintentionally
 * overwrite each other.
 */
model ObjectVersion {
  Index?: uint64;
}

/** Platform represents the platform (Arch/OS). */
model Platform {
  /**
   * Architecture represents the hardware architecture (for example,
   * `x86_64`).
   */
  Architecture?: string;
  /** OS represents the Operating System (for example, `linux` or `windows`). */
  OS?: string;
}

/**
 * Commit holds the Git-commit (SHA1) that a binary was built from, as
 * reported in the version-string of external tools, such as `containerd`,
 * or `runC`.
 */
model Commit {
  /** Actual commit ID of external tool. */
  ID?: string;
}

model ErrorDetail {
  code?: int32;
  message?: string;
}

model ProgressDetail {
  current?: int32;
  total?: int32;
}
