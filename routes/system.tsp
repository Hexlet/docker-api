import "@typespec/http";
import "@typespec/openapi";

import "../models/auth.tsp";
import "../models/common.tsp";
import "../models/containers.tsp";
import "../models/images.tsp";
import "../models/system.tsp";
import "../models/volumes.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** Check auth configuration */
@post
@route("/auth")
op SystemAuth(@body body: AuthConfig): AuthResponse;

/** Get system information */
@get
@route("/info")
op SystemInfoOp(): SystemInfo;

/** Get version */
@get
@route("/version")
op SystemVersionOp(): SystemVersion;

/** Ping */
@get
@route("/_ping")
op SystemPing(): string;

/** Ping */
@head
@route("/_ping")
op SystemPingHead(): string;

/** Monitor events */
@get
@route("/events")
op SystemEvents(@query since?: string, @query until?: string, @query filters?: string): EventMessage;

/** Get data usage information */
@get
@route("/system/df")
op SystemDataUsage(@query type?: "container" | "image" | "volume" | "build-cache"[], @query verbose?: boolean): {
  ImagesDiskUsage?: ImagesDiskUsage;
  ContainersDiskUsage?: ContainersDiskUsage;
  VolumesDiskUsage?: VolumesDiskUsage;
  BuildCacheDiskUsage?: BuildCacheDiskUsage;
};

/** Initialize interactive session */
@post
@route("/session")
op Session(): void;
