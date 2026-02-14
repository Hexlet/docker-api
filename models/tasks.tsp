import "@typespec/http";
import "@typespec/openapi";

import "./common.tsp";
import "./containers.tsp";
import "./mounts.tsp";
import "./networks.tsp";
import "./plugins.tsp";
import "./services.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

model Task {
  /** The ID of the task. */
  ID?: string;
  Version?: ObjectVersion;
  CreatedAt?: utcDateTime;
  UpdatedAt?: utcDateTime;
  /** Name of the task. */
  Name?: string;
  /** User-defined key/value metadata. */
  Labels?: Record<string>;
  Spec?: TaskSpec;
  /** The ID of the service this task is part of. */
  ServiceID?: string;
  Slot?: int32;
  /** The ID of the node that this task is on. */
  NodeID?: string;
  AssignedGenericResources?: GenericResources;
  Status?: TaskStatus;
  DesiredState?: TaskState;
  /**
   * If the Service this Task belongs to is a job-mode service, contains
   * the JobIteration of the Service this Task was created for. Absent if
   * the Task was created for a Replicated or Global Service.
   */
  JobIteration?: ObjectVersion;
}

/** User modifiable task configuration. */
model TaskSpec {
  /**
   * Plugin spec for the service.  *(Experimental release only.)*
   *
   * <p><br /></p>
   *
   * > **Note**: ContainerSpec, NetworkAttachmentSpec, and PluginSpec are
   * > mutually exclusive. PluginSpec is only used when the Runtime field
   * > is set to `plugin`. NetworkAttachmentSpec is used when the Runtime
   * > field is set to `attachment`.
   */
  PluginSpec?: {
    Name?: string;
    Remote?: string;
    Disabled?: boolean;
    PluginPrivilege?: PluginPrivilege[];
  };
  /**
   * Container spec for the service.
   *
   * <p><br /></p>
   *
   * > **Note**: ContainerSpec, NetworkAttachmentSpec, and PluginSpec are
   * > mutually exclusive. PluginSpec is only used when the Runtime field
   * > is set to `plugin`. NetworkAttachmentSpec is used when the Runtime
   * > field is set to `attachment`.
   */
  ContainerSpec?: {
    Image?: string;
    Labels?: Record<string>;
    Command?: string[];
    Args?: string[];
    Hostname?: string;
    Env?: string[];
    Dir?: string;
    User?: string;
    Groups?: string[];
    Privileges?: {
      CredentialSpec?: {
        Config?: string;
        File?: string;
        Registry?: string;
      };
      SELinuxContext?: {
        Disable?: boolean;
        User?: string;
        Role?: string;
        Type?: string;
        Level?: string;
      };
      Seccomp?: {
        Mode?: "default" | "unconfined" | "custom";
        Profile?: string;
      };
      AppArmor?: {
        Mode?: "default" | "disabled";
      };
      NoNewPrivileges?: boolean;
    };
    TTY?: boolean;
    OpenStdin?: boolean;
    ReadOnly?: boolean;
    Mounts?: Mount[];
    StopSignal?: string;
    StopGracePeriod?: int64;
    HealthCheck?: HealthConfig;
    Hosts?: string[];
    DNSConfig?: {
      Nameservers?: string[];
      Search?: string[];
      Options?: string[];
    };
    Secrets?: {
      File?: {
        Name?: string;
        UID?: string;
        GID?: string;
        Mode?: uint32;
      };
      SecretID?: string;
      SecretName?: string;
    }[];
    OomScoreAdj?: int64;
    Configs?: {
      File?: {
        Name?: string;
        UID?: string;
        GID?: string;
        Mode?: uint32;
      };
      Runtime?: Record<unknown>;
      ConfigID?: string;
      ConfigName?: string;
    }[];
    Isolation?: "default" | "process" | "hyperv" | "";
    `Init`?: boolean | null;
    Sysctls?: Record<string>;
    CapabilityAdd?: string[];
    CapabilityDrop?: string[];
    Ulimits?: {
      Name?: string;
      Soft?: int32;
      Hard?: int32;
    }[];
  };
  /**
   * Read-only spec type for non-swarm containers attached to swarm overlay
   * networks.
   *
   * <p><br /></p>
   *
   * > **Note**: ContainerSpec, NetworkAttachmentSpec, and PluginSpec are
   * > mutually exclusive. PluginSpec is only used when the Runtime field
   * > is set to `plugin`. NetworkAttachmentSpec is used when the Runtime
   * > field is set to `attachment`.
   */
  NetworkAttachmentSpec?: {
    ContainerID?: string;
  };
  /**
   * Resource requirements which apply to each individual container created
   * as part of the service.
   */
  Resources?: {
    Limits?: Limit;
    Reservations?: ResourceObject;
    SwapBytes?: int64 | null;
    MemorySwappiness?: int64 | null;
  };
  /**
   * Specification for the restart policy which applies to containers
   * created as part of this service.
   */
  RestartPolicy?: {
    Condition?: "none" | "on-failure" | "any";
    Delay?: int64;
    MaxAttempts?: int64;
    Window?: int64;
  };
  Placement?: {
    Constraints?: string[];
    Preferences?: {
      Spread?: {
        SpreadDescriptor?: string;
      };
    }[];
    MaxReplicas?: int64;
    Platforms?: Platform[];
  };
  /**
   * A counter that triggers an update even if no relevant parameters have
   * been changed.
   */
  ForceUpdate?: uint64;
  /** Runtime is the type of runtime specified for the task executor. */
  Runtime?: string;
  /** Specifies which networks the service should attach to. */
  Networks?: NetworkAttachmentConfig[];
  /**
   * Specifies the log driver to use for tasks created from this spec. If
   * not present, the default one for the swarm will be used, finally
   * falling back to the engine default if not specified.
   */
  LogDriver?: {
    Name?: string;
    Options?: Record<string>;
  };
}

union TaskState {
  "new",
  "allocated",
  "pending",
  "assigned",
  "accepted",
  "preparing",
  "ready",
  "starting",
  "running",
  "complete",
  "shutdown",
  "failed",
  "rejected",
  "remove",
  "orphaned",
}

/** represents the status of a task. */
model TaskStatus {
  Timestamp?: utcDateTime;
  State?: TaskState;
  Message?: string;
  Err?: string;
  ContainerStatus?: ContainerStatus;
  PortStatus?: PortStatus;
}

/**
 * represents the port status of a task's host ports whose service has published host ports
 */
model PortStatus {
  Ports?: EndpointPortConfig[];
}
