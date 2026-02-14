import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/exec.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** Start an exec instance */
@post
@route("/exec/{id}/start")
op ExecStart(@path id: string, @body body: {
  Detach?: boolean;
  Tty?: boolean;
  ConsoleSize?: int32[] | null;
}): void;

/** Resize an exec instance */
@post
@route("/exec/{id}/resize")
op ExecResize(@path id: string, @query h: int32, @query w: int32): void;

/** Inspect an exec instance */
@get
@route("/exec/{id}/json")
op ExecInspect(@path id: string): {
  CanRemove?: boolean;
  DetachKeys?: string;
  ID?: string;
  Running?: boolean;
  ExitCode?: int32;
  ProcessConfig?: ProcessConfig;
  OpenStdin?: boolean;
  OpenStderr?: boolean;
  OpenStdout?: boolean;
  ContainerID?: string;
  Pid?: int32;
};
