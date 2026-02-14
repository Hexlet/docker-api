import "@typespec/http";
import "@typespec/openapi";

import "../models/common.tsp";
import "../models/containers.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** List containers */
@get
@route("/containers/json")
op ContainerList(@query all?: boolean, @query limit?: int32, @query size?: boolean, @query filters?: string): ContainerSummary[];

/** Create a container */
@post
@route("/containers/create")
op ContainerCreate(@query name?: string, @query platform?: string, @body body: ContainerConfig): ContainerCreateResponse;

/** Inspect a container */
@get
@route("/containers/{id}/json")
op ContainerInspect(@path id: string, @query size?: boolean): ContainerInspectResponse;

/** List processes running inside a container */
@get
@route("/containers/{id}/top")
op ContainerTop(@path id: string, @query ps_args?: string): ContainerTopResponse;

/** Get container logs */
@get
@route("/containers/{id}/logs")
op ContainerLogs(@path id: string, @query follow?: boolean, @query stdout?: boolean, @query stderr?: boolean, @query since?: int32, @query until?: int32, @query timestamps?: boolean, @query tail?: string): bytes;

/** Get changes on a container’s filesystem */
@get
@route("/containers/{id}/changes")
op ContainerChanges(@path id: string): FilesystemChange[];

/** Export a container */
@get
@route("/containers/{id}/export")
op ContainerExport(@path id: string): void;

/** Get container stats based on resource usage */
@get
@route("/containers/{id}/stats")
op ContainerStats(@path id: string, @query stream?: boolean, @query("one-shot") one_shot?: boolean): ContainerStatsResponse;

/** Resize a container TTY */
@post
@route("/containers/{id}/resize")
op ContainerResize(@path id: string, @query h: int32, @query w: int32): void;

/** Start a container */
@post
@route("/containers/{id}/start")
op ContainerStart(@path id: string, @query detachKeys?: string): void;

/** Stop a container */
@post
@route("/containers/{id}/stop")
op ContainerStop(@path id: string, @query signal?: string, @query t?: int32): void;

/** Restart a container */
@post
@route("/containers/{id}/restart")
op ContainerRestart(@path id: string, @query signal?: string, @query t?: int32): void;

/** Kill a container */
@post
@route("/containers/{id}/kill")
op ContainerKill(@path id: string, @query signal?: string): void;

/** Update a container */
@post
@route("/containers/{id}/update")
op ContainerUpdate(@path id: string, @body body: Resources): ContainerUpdateResponse;

/** Rename a container */
@post
@route("/containers/{id}/rename")
op ContainerRename(@path id: string, @query name: string): void;

/** Pause a container */
@post
@route("/containers/{id}/pause")
op ContainerPause(@path id: string): void;

/** Unpause a container */
@post
@route("/containers/{id}/unpause")
op ContainerUnpause(@path id: string): void;

/** Attach to a container */
@post
@route("/containers/{id}/attach")
op ContainerAttach(@path id: string, @query detachKeys?: string, @query logs?: boolean, @query stream?: boolean, @query stdin?: boolean, @query stdout?: boolean, @query stderr?: boolean): void;

/** Attach to a container via a websocket */
@get
@route("/containers/{id}/attach/ws")
op ContainerAttachWebsocket(@path id: string, @query detachKeys?: string, @query logs?: boolean, @query stream?: boolean, @query stdin?: boolean, @query stdout?: boolean, @query stderr?: boolean): void;

/** Wait for a container */
@post
@route("/containers/{id}/wait")
op ContainerWait(@path id: string, @query condition?: "not-running" | "next-exit" | "removed"): ContainerWaitResponse;

/** Remove a container */
@delete
@route("/containers/{id}")
op ContainerDelete(@path id: string, @query v?: boolean, @query force?: boolean, @query link?: boolean): void;

/** Get an archive of a filesystem resource in a container */
@get
@route("/containers/{id}/archive")
op ContainerArchive(@path id: string, @query path: string): void;

/** Extract an archive of files or folders to a directory in a container */
@put
@route("/containers/{id}/archive")
op PutContainerArchive(@path id: string, @query path: string, @query noOverwriteDirNonDir?: string, @query copyUIDGID?: string, @body body: bytes): void;

/** Get information about files in a container */
@head
@route("/containers/{id}/archive")
op ContainerArchiveInfo(@path id: string, @query path: string): void;

/** Delete stopped containers */
@post
@route("/containers/prune")
op ContainerPrune(@query filters?: string): {
  ContainersDeleted?: string[];
  SpaceReclaimed?: int64;
};

/** Create an exec instance */
@post
@route("/containers/{id}/exec")
op ContainerExec(@path id: string, @body body: {
  AttachStdin?: boolean;
  AttachStdout?: boolean;
  AttachStderr?: boolean;
  ConsoleSize?: int32[] | null;
  DetachKeys?: string;
  Tty?: boolean;
  Env?: string[];
  Cmd?: string[];
  Privileged?: boolean;
  User?: string;
  WorkingDir?: string;
}): IDResponse;
