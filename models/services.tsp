import "@typespec/http";
import "@typespec/openapi";

import "./common.tsp";
import "./networks.tsp";
import "./tasks.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

model Service {
  ID?: string;
  Version?: ObjectVersion;
  CreatedAt?: utcDateTime;
  UpdatedAt?: utcDateTime;
  Spec?: ServiceSpec;
  Endpoint?: {
    Spec?: EndpointSpec;
    Ports?: EndpointPortConfig[];
    VirtualIPs?: {
      NetworkID?: string;
      Addr?: string;
    }[];
  };
  /** The status of a service update. */
  UpdateStatus?: {
    State?: "updating" | "paused" | "completed";
    StartedAt?: utcDateTime;
    CompletedAt?: utcDateTime;
    Message?: string;
  };
  /**
   * The status of the service's tasks. Provided only when requested as
   * part of a ServiceList operation.
   */
  ServiceStatus?: {
    RunningTasks?: uint64;
    DesiredTasks?: uint64;
    CompletedTasks?: uint64;
  };
  /**
   * The status of the service when it is in one of ReplicatedJob or
   * GlobalJob modes. Absent on Replicated and Global mode services. The
   * JobIteration is an ObjectVersion, but unlike the Service's version,
   * does not need to be sent with an update request.
   */
  JobStatus?: {
    JobIteration?: ObjectVersion;
    LastExecution?: utcDateTime;
  };
}

/** User modifiable configuration for a service. */
model ServiceSpec {
  /** Name of the service. */
  Name?: string;
  /** User-defined key/value metadata. */
  Labels?: Record<string>;
  TaskTemplate?: TaskSpec;
  /** Scheduling mode for the service. */
  Mode?: {
    Replicated?: {
      Replicas?: int64;
    };
    Global?: Record<unknown>;
    ReplicatedJob?: {
      MaxConcurrent?: int64;
      TotalCompletions?: int64;
    };
    GlobalJob?: Record<unknown>;
  };
  /** Specification for the update strategy of the service. */
  UpdateConfig?: {
    Parallelism?: int64;
    Delay?: int64;
    FailureAction?: "continue" | "pause" | "rollback";
    Monitor?: int64;
    MaxFailureRatio?: float64;
    Order?: "stop-first" | "start-first";
  };
  /** Specification for the rollback strategy of the service. */
  RollbackConfig?: {
    Parallelism?: int64;
    Delay?: int64;
    FailureAction?: "continue" | "pause";
    Monitor?: int64;
    MaxFailureRatio?: float64;
    Order?: "stop-first" | "start-first";
  };
  /**
   * Specifies which networks the service should attach to.
   *
   * Deprecated: This field is deprecated since v1.44. The Networks field in TaskSpec should be used instead.
   */
  Networks?: NetworkAttachmentConfig[];
  EndpointSpec?: EndpointSpec;
}

/** Properties that can be configured to access and load balance a service. */
model EndpointSpec {
  /** The mode of resolution to use for internal load balancing between tasks. */
  Mode?: "vip" | "dnsrr";
  /**
   * List of exposed ports that this service is accessible on from the
   * outside. Ports can only be provided if `vip` resolution mode is used.
   */
  Ports?: EndpointPortConfig[];
}

model EndpointPortConfig {
  Name?: string;
  Protocol?: "tcp" | "udp" | "sctp";
  /** The port inside the container. */
  TargetPort?: int32;
  /** The port on the swarm hosts. */
  PublishedPort?: int32;
  /**
   * The mode in which port is published.
   *
   * <p><br /></p>
   *
   * - "ingress" makes the target port accessible on every node,
   *   regardless of whether there is a task for the service running on
   *   that node or not.
   * - "host" bypasses the routing mesh and publish the port directly on
   *   the swarm node where that service is running.
   */
  PublishMode?: "ingress" | "host";
}

/**
 * contains the information returned to a client on the
 * creation of a new service.
 */
model ServiceCreateResponse {
  /** The ID of the created service. */
  ID?: string;
  /**
   * Optional warning message.
   *
   * FIXME(thaJeztah): this should have "omitempty" in the generated type.
   */
  Warnings?: string[] | null;
}

model ServiceUpdateResponse {
  /** Optional warning messages */
  Warnings?: string[];
}
