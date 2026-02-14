import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/services.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List services */
@get
@route("/services")
op ServiceList(@query filters?: string, @query status?: boolean): Service[];

/** Create a service */
@post
@route("/services/create")
op ServiceCreate(@header("X-Registry-Auth") X_Registry_Auth?: string, @body body: ServiceSpec): ServiceCreateResponse;

/** Inspect a service */
@get
@route("/services/{id}")
op ServiceInspect(@path id: string, @query insertDefaults?: boolean): Service;

/** Delete a service */
@delete
@route("/services/{id}")
op ServiceDelete(@path id: string): void;

/** Update a service */
@post
@route("/services/{id}/update")
op ServiceUpdate(@path id: string, @query version: int32, @query registryAuthFrom?: "spec" | "previous-spec", @query rollback?: string, @header("X-Registry-Auth") X_Registry_Auth?: string, @body body: ServiceSpec): ServiceUpdateResponse;

/** Get service logs */
@get
@route("/services/{id}/logs")
op ServiceLogs(@path id: string, @query details?: boolean, @query follow?: boolean, @query stdout?: boolean, @query stderr?: boolean, @query since?: int32, @query timestamps?: boolean, @query tail?: string): bytes;
