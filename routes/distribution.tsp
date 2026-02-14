import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/system.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** Get image information from the registry */
@get
@route("/distribution/{name}/json")
op DistributionInspectOp(@path name: string): DistributionInspect;
