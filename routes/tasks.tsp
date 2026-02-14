import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/tasks.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List tasks */
@get
@route("/tasks")
op TaskList(@query filters?: string): Task[];

/** Inspect a task */
@get
@route("/tasks/{id}")
op TaskInspect(@path id: string): Task;

/** Get task logs */
@get
@route("/tasks/{id}/logs")
op TaskLogs(@path id: string, @query details?: boolean, @query follow?: boolean, @query stdout?: boolean, @query stderr?: boolean, @query since?: int32, @query timestamps?: boolean, @query tail?: string): bytes;
