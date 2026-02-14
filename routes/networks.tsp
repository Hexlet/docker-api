import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/networks.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List networks */
@get
@route("/networks")
op NetworkList(@query filters?: string): NetworkSummary[];

/** Inspect a network */
@get
@route("/networks/{id}")
op NetworkInspectOp(@path id: string, @query verbose?: boolean, @query scope?: string): NetworkInspect;

/** Remove a network */
@delete
@route("/networks/{id}")
op NetworkDelete(@path id: string): void;

/** Create a network */
@post
@route("/networks/create")
op NetworkCreate(@body body: {
  Name: string;
  Driver?: string;
  Scope?: string;
  Internal?: boolean;
  Attachable?: boolean;
  Ingress?: boolean;
  ConfigOnly?: boolean;
  ConfigFrom?: ConfigReference;
  IPAM?: IPAM;
  EnableIPv4?: boolean;
  EnableIPv6?: boolean;
  Options?: Record<string>;
  Labels?: Record<string>;
}): NetworkCreateResponse;

/** Connect a container to a network */
@post
@route("/networks/{id}/connect")
op NetworkConnect(@path id: string, @body body: NetworkConnectRequest): void;

/** Disconnect a container from a network */
@post
@route("/networks/{id}/disconnect")
op NetworkDisconnect(@path id: string, @body body: NetworkDisconnectRequest): void;

/** Delete unused networks */
@post
@route("/networks/prune")
op NetworkPrune(@query filters?: string): {
  NetworksDeleted?: string[];
};
