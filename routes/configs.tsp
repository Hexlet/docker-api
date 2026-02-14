import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/configs.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List configs */
@get
@route("/configs")
op ConfigList(@query filters?: string): Config[];

/** Create a config */
@post
@route("/configs/create")
op ConfigCreate(@body body: ConfigSpec): IDResponse;

/** Inspect a config */
@get
@route("/configs/{id}")
op ConfigInspect(@path id: string): Config;

/** Delete a config */
@delete
@route("/configs/{id}")
op ConfigDelete(@path id: string): void;

/** Update a Config */
@post
@route("/configs/{id}/update")
op ConfigUpdate(@path id: string, @query version: int64, @body body: ConfigSpec): void;
