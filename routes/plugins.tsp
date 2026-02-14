import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/plugins.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List plugins */
@get
@route("/plugins")
op PluginList(@query filters?: string): Plugin[];

/** Get plugin privileges */
@get
@route("/plugins/privileges")
op GetPluginPrivileges(@query remote: string): PluginPrivilege[];

/** Install a plugin */
@post
@route("/plugins/pull")
op PluginPull(@query remote: string, @query name?: string, @header("X-Registry-Auth") X_Registry_Auth?: string, @body body: PluginPrivilege[]): void;

/** Inspect a plugin */
@get
@route("/plugins/{name}/json")
op PluginInspect(@path name: string): Plugin;

/** Remove a plugin */
@delete
@route("/plugins/{name}")
op PluginDelete(@path name: string, @query force?: boolean): Plugin;

/** Enable a plugin */
@post
@route("/plugins/{name}/enable")
op PluginEnable(@path name: string, @query timeout?: int32): void;

/** Disable a plugin */
@post
@route("/plugins/{name}/disable")
op PluginDisable(@path name: string, @query force?: boolean): void;

/** Upgrade a plugin */
@post
@route("/plugins/{name}/upgrade")
op PluginUpgrade(@path name: string, @query remote: string, @header("X-Registry-Auth") X_Registry_Auth?: string, @body body: PluginPrivilege[]): void;

/** Create a plugin */
@post
@route("/plugins/create")
op PluginCreate(@query name: string, @body body: bytes): void;

/** Push a plugin */
@post
@route("/plugins/{name}/push")
op PluginPush(@path name: string): void;

/** Configure a plugin */
@post
@route("/plugins/{name}/set")
op PluginSet(@path name: string, @body body: string[]): void;
