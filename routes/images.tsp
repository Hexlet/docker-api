import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/containers.tsp";
import "../models/images.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List Images */
@get
@route("/images/json")
op ImageList(@query all?: boolean, @query filters?: string, @query("shared-size") shared_size?: boolean, @query digests?: boolean, @query manifests?: boolean): ImageSummary[];

/** Build an image */
@post
@route("/build")
op ImageBuild(@query dockerfile?: string, @query t?: string, @query extrahosts?: string, @query remote?: string, @query q?: boolean, @query nocache?: boolean, @query cachefrom?: string, @query pull?: string, @query rm?: boolean, @query forcerm?: boolean, @query memory?: int32, @query memswap?: int32, @query cpushares?: int32, @query cpusetcpus?: string, @query cpuperiod?: int32, @query cpuquota?: int32, @query buildargs?: string, @query shmsize?: int32, @query squash?: boolean, @query labels?: string, @query networkmode?: string, @header("Content-type") Content_type?: "application/x-tar", @header("X-Registry-Config") X_Registry_Config?: string, @query platform?: string, @query target?: string, @query outputs?: string, @query version?: "1" | "2", @body body: bytes): void;

/** Delete builder cache */
@post
@route("/build/prune")
op BuildPrune(@query("reserved-space") reserved_space?: int64, @query("max-used-space") max_used_space?: int64, @query("min-free-space") min_free_space?: int64, @query all?: boolean, @query filters?: string): {
  CachesDeleted?: string[];
  SpaceReclaimed?: int64;
};

/** Create an image */
@post
@route("/images/create")
op ImageCreate(@query fromImage?: string, @query fromSrc?: string, @query repo?: string, @query tag?: string, @query message?: string, @header("X-Registry-Auth") X_Registry_Auth?: string, @query changes?: string[], @query platform?: string, @body body: string): void;

/** Inspect an image */
@get
@route("/images/{name}/json")
op ImageInspectOp(@path name: string, @query manifests?: boolean): ImageInspect;

/** Get the history of an image */
@get
@route("/images/{name}/history")
op ImageHistory(@path name: string, @query platform?: string): ImageHistoryResponseItem[];

/** Push an image */
@post
@route("/images/{name}/push")
op ImagePush(@path name: string, @query tag?: string, @query platform?: string, @header("X-Registry-Auth") X_Registry_Auth: string): void;

/** Tag an image */
@post
@route("/images/{name}/tag")
op ImageTag(@path name: string, @query repo?: string, @query tag?: string): void;

/** Remove an image */
@delete
@route("/images/{name}")
op ImageDelete(@path name: string, @query force?: boolean, @query noprune?: boolean, @query platforms?: string[]): ImageDeleteResponseItem[];

/** Search images */
@get
@route("/images/search")
op ImageSearch(@query term: string, @query limit?: int32, @query filters?: string): {
  description?: string;
  is_official?: boolean;
  is_automated?: boolean;
  name?: string;
  star_count?: int32;
}[];

/** Delete unused images */
@post
@route("/images/prune")
op ImagePrune(@query filters?: string): {
  ImagesDeleted?: ImageDeleteResponseItem[];
  SpaceReclaimed?: int64;
};

/** Create a new image from a container */
@post
@route("/commit")
op ImageCommit(@query container?: string, @query repo?: string, @query tag?: string, @query comment?: string, @query author?: string, @query pause?: boolean, @query changes?: string, @body body: ContainerConfig): IDResponse;

/** Export an image */
@get
@route("/images/{name}/get")
op ImageGet(@path name: string, @query platform?: string[]): bytes;

/** Export several images */
@get
@route("/images/get")
op ImageGetAll(@query names?: string[], @query platform?: string[]): bytes;

/** Import images */
@post
@route("/images/load")
op ImageLoad(@query quiet?: boolean, @query platform?: string[], @body body: bytes): void;
