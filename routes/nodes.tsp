import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/nodes.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List nodes */
@get
@route("/nodes")
op NodeList(@query filters?: string): Node[];

/** Inspect a node */
@get
@route("/nodes/{id}")
op NodeInspect(@path id: string): Node;

/** Delete a node */
@delete
@route("/nodes/{id}")
op NodeDelete(@path id: string, @query force?: boolean): void;

/** Update a node */
@post
@route("/nodes/{id}/update")
op NodeUpdate(@path id: string, @query version: int64, @body body: NodeSpec): void;
