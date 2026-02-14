import "@typespec/http";
import "@typespec/openapi";

import "./common.tsp";
import "./containers.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

model Node {
  ID?: string;
  Version?: ObjectVersion;
  /**
   * Date and time at which the node was added to the swarm in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  CreatedAt?: utcDateTime;
  /**
   * Date and time at which the node was last updated in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  UpdatedAt?: utcDateTime;
  Spec?: NodeSpec;
  Description?: NodeDescription;
  Status?: NodeStatus;
  ManagerStatus?: ManagerStatus;
}

model NodeSpec {
  /** Name for the node. */
  Name?: string;
  /** User-defined key/value metadata. */
  Labels?: Record<string>;
  /** Role of the node. */
  Role?: "worker" | "manager";
  /** Availability of the node. */
  Availability?: "active" | "pause" | "drain";
}

/**
 * NodeDescription encapsulates the properties of the Node as reported by the
 * agent.
 */
model NodeDescription {
  Hostname?: string;
  Platform?: Platform;
  Resources?: ResourceObject;
  Engine?: EngineDescription;
  TLSInfo?: TLSInfo;
}

/**
 * NodeStatus represents the status of a node.
 *
 * It provides the current status of the node, as seen by the manager.
 */
model NodeStatus {
  State?: NodeState;
  Message?: string;
  /** IP address of the node. */
  Addr?: string;
}

/** NodeState represents the state of a node. */
union NodeState {
  "unknown",
  "down",
  "ready",
  "disconnected",
}

/**
 * ManagerStatus represents the status of a manager.
 *
 * It provides the current status of a node's manager component, if the node
 * is a manager.
 */
model ManagerStatus {
  Leader?: boolean;
  Reachability?: Reachability;
  /** The IP address and port at which the manager is reachable. */
  Addr?: string;
}

/** Reachability represents the reachability of a node. */
union Reachability {
  "unknown",
  "unreachable",
  "reachable",
}

/** EngineDescription provides information about an engine. */
model EngineDescription {
  EngineVersion?: string;
  Labels?: Record<string>;
  Plugins?: {
    Type?: string;
    Name?: string;
  }[];
}

/**
 * Information about the issuer of leaf TLS certificates and the trusted root
 * CA certificate.
 */
model TLSInfo {
  /**
   * The root CA certificate(s) that are used to validate leaf TLS
   * certificates.
   */
  TrustRoot?: string;
  /** The base64-url-safe-encoded raw subject bytes of the issuer. */
  CertIssuerSubject?: string;
  /** The base64-url-safe-encoded raw public key bytes of the issuer. */
  CertIssuerPublicKey?: string;
}
