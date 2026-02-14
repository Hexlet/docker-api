import "@typespec/http";
import "@typespec/openapi";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

model ProcessConfig {
  privileged?: boolean;
  user?: string;
  tty?: boolean;
  entrypoint?: string;
  arguments?: string[];
}
