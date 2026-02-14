import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/swarm.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** Inspect swarm */
@get
@route("/swarm")
op SwarmInspect(): Swarm;

/** Initialize a new swarm */
@post
@route("/swarm/init")
op SwarmInit(@body body: {
  ListenAddr?: string;
  AdvertiseAddr?: string;
  DataPathAddr?: string;
  DataPathPort?: uint32;
  DefaultAddrPool?: string[];
  ForceNewCluster?: boolean;
  SubnetSize?: uint32;
  Spec?: SwarmSpec;
}): string;

/** Join an existing swarm */
@post
@route("/swarm/join")
op SwarmJoin(@body body: {
  ListenAddr?: string;
  AdvertiseAddr?: string;
  DataPathAddr?: string;
  RemoteAddrs?: string[];
  JoinToken?: string;
}): void;

/** Leave a swarm */
@post
@route("/swarm/leave")
op SwarmLeave(@query force?: boolean): void;

/** Update a swarm */
@post
@route("/swarm/update")
op SwarmUpdate(@query version: int64, @query rotateWorkerToken?: boolean, @query rotateManagerToken?: boolean, @query rotateManagerUnlockKey?: boolean, @body body: SwarmSpec): void;

/** Get the unlock key */
@get
@route("/swarm/unlockkey")
op SwarmUnlockkey(): {
  UnlockKey?: string;
};

/** Unlock a locked manager */
@post
@route("/swarm/unlock")
op SwarmUnlock(@body body: {
  UnlockKey?: string;
}): void;
