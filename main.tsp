import "@typespec/http";
import "@typespec/openapi";
import "@typespec/openapi3";

import "./models/common.tsp";
import "./models/mounts.tsp";
import "./models/containers.tsp";
import "./models/images.tsp";
import "./models/networks.tsp";
import "./models/volumes.tsp";
import "./models/services.tsp";
import "./models/tasks.tsp";
import "./models/nodes.tsp";
import "./models/swarm.tsp";
import "./models/secrets.tsp";
import "./models/configs.tsp";
import "./models/plugins.tsp";
import "./models/exec.tsp";
import "./models/auth.tsp";
import "./models/system.tsp";

import "./routes/containers.tsp";
import "./routes/images.tsp";
import "./routes/networks.tsp";
import "./routes/volumes.tsp";
import "./routes/exec.tsp";
import "./routes/services.tsp";
import "./routes/tasks.tsp";
import "./routes/nodes.tsp";
import "./routes/swarm.tsp";
import "./routes/secrets.tsp";
import "./routes/configs.tsp";
import "./routes/plugins.tsp";
import "./routes/system.tsp";
import "./routes/distribution.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

@service(#{
  title: "Docker Engine API",
})
@info(#{
  version: "1.53",
})
@server("http://localhost:2375", "Docker Engine")
namespace DockerEngine;
