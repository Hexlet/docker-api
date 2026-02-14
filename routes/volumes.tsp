import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/volumes.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List volumes */
@get
@route("/volumes")
op VolumeList(@query filters?: string): VolumeListResponse;

/** Create a volume */
@post
@route("/volumes/create")
op VolumeCreate(@body body: VolumeCreateRequest): Volume;

/** Inspect a volume */
@get
@route("/volumes/{name}")
op VolumeInspect(@path name: string): Volume;

/** "Update a volume. Valid only for Swarm cluster volumes" */
@put
@route("/volumes/{name}")
op VolumeUpdate(@path name: string, @query version: int64, @body body: {
  Spec?: ClusterVolumeSpec;
}): void;

/** Remove a volume */
@delete
@route("/volumes/{name}")
op VolumeDelete(@path name: string, @query force?: boolean): void;

/** Delete unused volumes */
@post
@route("/volumes/prune")
op VolumePrune(@query filters?: string): {
  VolumesDeleted?: string[];
  SpaceReclaimed?: int64;
};
