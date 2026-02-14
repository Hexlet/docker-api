import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/secrets.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List secrets */
@get
@route("/secrets")
op SecretList(@query filters?: string): Secret[];

/** Create a secret */
@post
@route("/secrets/create")
op SecretCreate(@body body: SecretSpec): IDResponse;

/** Inspect a secret */
@get
@route("/secrets/{id}")
op SecretInspect(@path id: string): Secret;

/** Delete a secret */
@delete
@route("/secrets/{id}")
op SecretDelete(@path id: string): void;

/** Update a Secret */
@post
@route("/secrets/{id}/update")
op SecretUpdate(@path id: string, @query version: int64, @body body: SecretSpec): void;
