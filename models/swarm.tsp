import "@typespec/http";
import "@typespec/openapi";

import "./common.tsp";
import "./nodes.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

model Swarm {
  ...ClusterInfo;
  JoinTokens?: JoinTokens;
}

/** User modifiable swarm configuration. */
model SwarmSpec {
  /** Name of the swarm. */
  Name?: string;
  /** User-defined key/value metadata. */
  Labels?: Record<string>;
  /** Orchestration configuration. */
  Orchestration?: {
    TaskHistoryRetentionLimit?: int64;
  } | null;
  /** Raft configuration. */
  Raft?: {
    SnapshotInterval?: uint64;
    KeepOldSnapshots?: uint64;
    LogEntriesForSlowFollowers?: uint64;
    ElectionTick?: int32;
    HeartbeatTick?: int32;
  };
  /** Dispatcher configuration. */
  Dispatcher?: {
    HeartbeatPeriod?: int64;
  } | null;
  /** CA configuration. */
  CAConfig?: {
    NodeCertExpiry?: int64;
    ExternalCAs?: {
      Protocol?: "cfssl";
      URL?: string;
      Options?: Record<string>;
      CACert?: string;
    }[];
    SigningCACert?: string;
    SigningCAKey?: string;
    ForceRotate?: uint64;
  } | null;
  /** Parameters related to encryption-at-rest. */
  EncryptionConfig?: {
    AutoLockManagers?: boolean;
  };
  /** Defaults for creating tasks in this cluster. */
  TaskDefaults?: {
    LogDriver?: {
      Name?: string;
      Options?: Record<string>;
    };
  };
}

/**
 * ClusterInfo represents information about the swarm as is returned by the
 * "/info" endpoint. Join-tokens are not included.
 */
model ClusterInfo {
  /** The ID of the swarm. */
  ID?: string;
  Version?: ObjectVersion;
  /**
   * Date and time at which the swarm was initialised in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  CreatedAt?: utcDateTime;
  /**
   * Date and time at which the swarm was last updated in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  UpdatedAt?: utcDateTime;
  Spec?: SwarmSpec;
  TLSInfo?: TLSInfo;
  /** Whether there is currently a root CA rotation in progress for the swarm */
  RootRotationInProgress?: boolean;
  /**
   * DataPathPort specifies the data path port number for data traffic.
   * Acceptable port range is 1024 to 49151.
   * If no port is set or is set to 0, the default port (4789) is used.
   */
  DataPathPort?: uint32;
  /**
   * Default Address Pool specifies default subnet pools for global scope
   * networks.
   */
  DefaultAddrPool?: string[];
  /**
   * SubnetSize specifies the subnet size of the networks created from the
   * default subnet pool.
   */
  SubnetSize?: uint32;
}

/** JoinTokens contains the tokens workers and managers need to join the swarm. */
model JoinTokens {
  /** The token workers can use to join the swarm. */
  Worker?: string;
  /** The token managers can use to join the swarm. */
  Manager?: string;
}

/** Represents generic information about swarm. */
model SwarmInfo {
  /** Unique identifier of for this node in the swarm. */
  NodeID?: string;
  /**
   * IP address at which this node can be reached by other nodes in the
   * swarm.
   */
  NodeAddr?: string;
  LocalNodeState?: LocalNodeState;
  ControlAvailable?: boolean;
  Error?: string;
  /** List of ID's and addresses of other managers in the swarm. */
  RemoteManagers?: PeerNode[] | null;
  /** Total number of nodes in the swarm. */
  Nodes?: int32 | null;
  /** Total number of managers in the swarm. */
  Managers?: int32 | null;
  Cluster?: ClusterInfo;
}

/** Current local status of this node. */
union LocalNodeState {
  "",
  "inactive",
  "pending",
  "active",
  "error",
  "locked",
}

/** Represents a peer-node in the swarm */
model PeerNode {
  /** Unique identifier of for this node in the swarm. */
  NodeID?: string;
  /** IP address and ports at which this node can be reached. */
  Addr?: string;
}
