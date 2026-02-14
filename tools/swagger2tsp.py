#!/usr/bin/env python3
"""Convert Swagger 2.0 YAML to TypeSpec files."""

import yaml
import os
import re
import sys

TSP_RESERVED = {
    "op", "model", "alias", "namespace", "enum", "union", "interface",
    "import", "using", "is", "extends", "scalar", "dec", "fn",
    "extern", "void", "never", "null", "true", "false", "unknown",
    "valueof", "const", "init", "if", "else", "projection", "return",
}

def safe_prop(name):
    """Make property name safe for TypeSpec."""
    n = name.replace("-", "_").replace(" ", "_")
    # Dots in property names
    if "." in n:
        n = n.replace(".", "_")
    if n.lower() in TSP_RESERVED or n in TSP_RESERVED:
        return f"`{n}`"
    if n and n[0].isdigit():
        return f"`{n}`"
    return n

def safe_param(name):
    """Make parameter name safe."""
    return name.replace("-", "_").replace(".", "_").replace(" ", "_")

def needs_encoded_name(original, safe):
    """Check if we need @encodedName decorator."""
    clean = safe.strip("`")
    return clean != original

MODEL_GROUPS = {
    "common": [
        "ErrorResponse", "IDResponse", "Driver", "ObjectVersion", "Platform",
        "Commit", "ErrorDetail", "ProgressDetail",
    ],
    "mounts": [
        "MountType", "MountPoint", "DeviceMapping", "DeviceRequest",
        "ThrottleDevice", "Mount",
    ],
    "containers": [
        "ContainerConfig", "ImageConfig", "HostConfig", "Resources",
        "RestartPolicy", "HealthConfig", "Health", "HealthcheckResult",
        "NetworkingConfig", "NetworkSettings",
        "ContainerInspectResponse", "ContainerSummary", "ContainerState",
        "ContainerCreateResponse", "ContainerUpdateResponse",
        "ContainerStatsResponse", "ContainerBlkioStats", "ContainerBlkioStatEntry",
        "ContainerCPUStats", "ContainerCPUUsage", "ContainerPidsStats",
        "ContainerThrottlingData", "ContainerMemoryStats", "ContainerNetworkStats",
        "ContainerStorageStats", "ContainerTopResponse", "ContainerWaitResponse",
        "ContainerWaitExitError", "FilesystemChange", "ChangeType",
        "ContainersDiskUsage", "ContainerStatus",
        "Limit", "ResourceObject", "GenericResources",
    ],
    "images": [
        "ImageInspect", "ImageSummary", "ImageHistoryResponseItem",
        "ImageDeleteResponseItem", "ImagesDiskUsage",
        "Identity", "BuildIdentity", "PullIdentity", "SignatureIdentity",
        "SignatureTimestamp", "SignatureTimestampType", "SignatureType",
        "KnownSignerIdentity", "SignerIdentity",
        "BuildInfo", "BuildCache", "BuildCacheDiskUsage",
        "ImageID", "CreateImageInfo", "PushImageInfo",
        "OCIDescriptor", "OCIPlatform", "ImageManifestSummary",
        "Storage", "RootFSStorage", "RootFSStorageSnapshot",
    ],
    "networks": [
        "Network", "NetworkSummary", "NetworkInspect", "NetworkStatus",
        "ServiceInfo", "NetworkTaskInfo",
        "IPAM", "IPAMConfig", "IPAMStatus", "SubnetStatus",
        "EndpointResource", "PeerInfo", "NetworkCreateResponse",
        "NetworkConnectRequest", "NetworkDisconnectRequest",
        "EndpointSettings", "EndpointIPAMConfig",
        "PortSummary", "PortMap", "PortBinding", "Address",
        "NetworkAttachmentConfig", "ConfigReference",
    ],
    "volumes": [
        "Volume", "VolumeCreateRequest", "VolumeListResponse",
        "VolumesDiskUsage", "ClusterVolume", "ClusterVolumeSpec",
        "Topology", "DriverData",
    ],
    "services": [
        "Service", "ServiceSpec", "EndpointSpec", "EndpointPortConfig",
        "ServiceCreateResponse", "ServiceUpdateResponse",
    ],
    "tasks": [
        "Task", "TaskSpec", "TaskState", "TaskStatus", "PortStatus",
    ],
    "nodes": [
        "Node", "NodeSpec", "NodeDescription", "NodeStatus", "NodeState",
        "ManagerStatus", "Reachability", "EngineDescription", "TLSInfo",
    ],
    "swarm": [
        "Swarm", "SwarmSpec", "ClusterInfo", "JoinTokens",
        "SwarmInfo", "LocalNodeState", "PeerNode",
    ],
    "secrets": ["Secret", "SecretSpec"],
    "configs": ["Config", "ConfigSpec"],
    "plugins": [
        "Plugin", "PluginMount", "PluginDevice", "PluginEnv", "PluginPrivilege",
    ],
    "exec": ["ProcessConfig"],
    "auth": ["AuthConfig", "AuthResponse"],
    "system": [
        "SystemVersion", "SystemInfo", "ContainerdInfo", "FirewallInfo",
        "NRIInfo", "DeviceInfo", "PluginsInfo", "RegistryServiceConfig",
        "IndexInfo", "Runtime", "EventMessage", "EventActor",
        "DistributionInspect",
    ],
}

ROUTE_GROUPS = {
    "containers": ["/containers/"],
    "images": ["/images/", "/build", "/commit"],
    "networks": ["/networks/"],
    "volumes": ["/volumes/"],
    "exec": ["/exec/"],
    "services": ["/services/"],
    "tasks": ["/tasks/"],
    "nodes": ["/nodes/"],
    "swarm": ["/swarm"],
    "secrets": ["/secrets/"],
    "configs": ["/configs/"],
    "plugins": ["/plugins/"],
    "system": ["/auth", "/info", "/version", "/_ping", "/events", "/system/", "/session"],
    "distribution": ["/distribution/"],
}

MODEL_TO_GROUP = {}
for group, models in MODEL_GROUPS.items():
    for m in models:
        MODEL_TO_GROUP[m] = group


def find_refs_in_schema(schema):
    refs = set()
    if isinstance(schema, dict):
        if "$ref" in schema:
            refs.add(schema["$ref"].split("/")[-1])
        for v in schema.values():
            refs.update(find_refs_in_schema(v))
    elif isinstance(schema, list):
        for item in schema:
            refs.update(find_refs_in_schema(item))
    return refs


def swagger_type_to_tsp(prop, defs, indent=0):
    if "$ref" in prop:
        return prop["$ref"].split("/")[-1]

    typ = prop.get("type")
    fmt = prop.get("format")

    if "allOf" in prop:
        parts = prop["allOf"]
        if len(parts) == 1:
            return swagger_type_to_tsp(parts[0], defs, indent)
        types = [swagger_type_to_tsp(p, defs, indent) for p in parts]
        return types[0]

    if "oneOf" in prop:
        parts = [swagger_type_to_tsp(p, defs, indent) for p in prop["oneOf"]]
        return " | ".join(parts)

    if typ == "string":
        if "enum" in prop:
            return " | ".join(f'"{v}"' for v in prop["enum"])
        if fmt in ("dateTime", "date-time"):
            return "utcDateTime"
        if fmt in ("binary", "byte"):
            return "bytes"
        return "string"

    if typ == "integer":
        m = {"int64": "int64", "int32": "int32", "uint16": "uint16", "uint32": "uint32", "uint64": "uint64"}
        return m.get(fmt, "int32")

    if typ == "number":
        return "float32" if fmt == "float" else "float64"

    if typ == "boolean":
        return "boolean"

    if typ == "array":
        items = prop.get("items", {})
        inner = swagger_type_to_tsp(items, defs, indent)
        # Wrap union types in parens for array
        if "|" in inner and not inner.startswith("("):
            inner = f"({inner})"
        return f"{inner}[]"

    if typ == "object" or (typ is None and ("properties" in prop or "additionalProperties" in prop)):
        if "additionalProperties" in prop and "properties" not in prop:
            ap = prop["additionalProperties"]
            if isinstance(ap, dict) and ap:
                return f"Record<{swagger_type_to_tsp(ap, defs, indent)}>"
            return "Record<unknown>"
        if "properties" in prop:
            return format_inline_model(prop, defs, indent)
        return "Record<unknown>"

    if typ is None:
        if "properties" in prop:
            return format_inline_model(prop, defs, indent)
        return "unknown"

    return "unknown"


def format_inline_model(schema, defs, indent=0):
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    pad = "  " * (indent + 1)
    pad_close = "  " * indent
    parts = ["{"]
    for pname, pschema in props.items():
        tsp_type = swagger_type_to_tsp(pschema, defs, indent + 1)
        nullable = pschema.get("x-nullable", False)
        sn = safe_prop(pname)
        opt = "?" if pname not in required else ""
        suf = " | null" if nullable else ""
        if needs_encoded_name(pname, sn):
            parts.append(f'{pad}@encodedName("application/json", "{pname}")')
        parts.append(f"{pad}{sn}{opt}: {tsp_type}{suf};")
    parts.append(f"{pad_close}}}")
    return "\n".join(parts)


def format_doc(desc, indent=0):
    if not desc:
        return ""
    pad = "  " * indent
    lines = desc.rstrip().split("\n")
    if len(lines) == 1 and len(lines[0]) < 80:
        # Escape */ in doc comments
        safe_line = lines[0].replace("*/", "* /")
        return f"{pad}/** {safe_line} */\n"
    r = f"{pad}/**\n"
    for line in lines:
        safe_line = line.rstrip().replace("*/", "* /")
        r += f"{pad} * {safe_line}\n" if line.strip() else f"{pad} *\n"
    r += f"{pad} */\n"
    return r


def emit_prop(pname, pschema, defs, required_set, indent=0):
    """Emit a single property with doc, @encodedName, etc."""
    pad = "  " * indent
    result = ""
    pdesc = pschema.get("description", "")
    if pdesc:
        result += format_doc(pdesc, indent)
    tsp_type = swagger_type_to_tsp(pschema, defs, indent)
    nullable = pschema.get("x-nullable", False)
    sn = safe_prop(pname)
    opt = "?" if pname not in required_set else ""
    suf = " | null" if nullable else ""
    if needs_encoded_name(pname, sn):
        result += f'{pad}@encodedName("application/json", "{pname}")\n'
    result += f"{pad}{sn}{opt}: {tsp_type}{suf};\n"
    return result


def generate_model(name, schema, defs, indent=0):
    pad = "  " * indent
    result = ""
    desc = schema.get("description", "")
    if desc:
        result += format_doc(desc, indent)

    typ = schema.get("type")

    # Enum
    if "enum" in schema and typ in ("string", None):
        vals = schema["enum"]
        result += f"{pad}union {name} {{\n"
        for v in vals:
            result += f'{pad}  "{v}",\n'
        result += f"{pad}}}\n"
        return result

    if "enum" in schema and typ == "integer":
        vals = schema["enum"]
        result += f"{pad}union {name} {{\n"
        for v in vals:
            result += f"{pad}  {v},\n"
        result += f"{pad}}}\n"
        return result

    # allOf
    if "allOf" in schema:
        all_of = schema["allOf"]
        extends = []
        extra_props = {}
        extra_required = set()
        for part in all_of:
            if "$ref" in part:
                extends.append(part["$ref"].split("/")[-1])
            else:
                extra_props.update(part.get("properties", {}))
                extra_required.update(part.get("required", []))

        result += f"{pad}model {name} {{\n"
        for ext in extends:
            result += f"{pad}  ...{ext};\n"

        for pname, pschema in extra_props.items():
            result += emit_prop(pname, pschema, defs, extra_required, indent + 1)
        result += f"{pad}}}\n"
        return result

    # Object
    if typ == "object" or (typ is None and "properties" in schema):
        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        ap = schema.get("additionalProperties")

        if not props and ap:
            if isinstance(ap, dict) and ap:
                val_type = swagger_type_to_tsp(ap, defs, indent)
            else:
                val_type = "unknown"
            result += f"{pad}alias {name} = Record<{val_type}>;\n"
            return result

        result += f"{pad}model {name} {{\n"

        if ap:
            if isinstance(ap, dict) and ap:
                val_type = swagger_type_to_tsp(ap, defs, indent + 1)
                result += f"{pad}  ...Record<{val_type}>;\n"
            else:
                result += f"{pad}  ...Record<unknown>;\n"

        for pname, pschema in props.items():
            result += emit_prop(pname, pschema, defs, required, indent + 1)
        result += f"{pad}}}\n"
        return result

    # Array
    if typ == "array":
        items = schema.get("items", {})
        item_type = swagger_type_to_tsp(items, defs, indent)
        result += f"{pad}alias {name} = {item_type}[];\n"
        return result

    # Simple scalar
    if typ == "string":
        result += f"{pad}scalar {name} extends string;\n"
        return result

    if typ == "integer":
        m = {"int64": "int64", "int32": "int32", "uint16": "uint16", "uint32": "uint32", "uint64": "uint64"}
        tsp_int = m.get(schema.get("format"), "int32")
        result += f"{pad}scalar {name} extends {tsp_int};\n"
        return result

    result += f"{pad}model {name} {{}}\n"
    return result


def get_imports_for_group(group_name, model_names, defs):
    imports = set()
    for mname in model_names:
        if mname not in defs:
            continue
        refs = find_refs_in_schema(defs[mname])
        for ref in refs:
            if ref in MODEL_TO_GROUP and MODEL_TO_GROUP[ref] != group_name:
                imports.add(MODEL_TO_GROUP[ref])
    return imports


def generate_model_file(group_name, model_names, defs):
    imports = get_imports_for_group(group_name, model_names, defs)
    lines = ['import "@typespec/http";', 'import "@typespec/openapi";', ""]
    for imp in sorted(imports):
        lines.append(f'import "./{imp}.tsp";')
    if imports:
        lines.append("")
    lines.append("using TypeSpec.Http;")
    lines.append("using TypeSpec.OpenAPI;")
    lines.append("")
    lines.append("namespace DockerEngine;")
    lines.append("")
    for mname in model_names:
        if mname not in defs:
            print(f"  Warning: {mname} not in definitions", file=sys.stderr)
            continue
        lines.append(generate_model(mname, defs[mname], defs))
    return "\n".join(lines)


def classify_route(path):
    for group, prefixes in ROUTE_GROUPS.items():
        for prefix in prefixes:
            if path.startswith(prefix) or path == prefix.rstrip("/"):
                return group
    return "system"


def param_to_tsp(param, defs):
    name = param.get("name", "param")
    loc = param.get("in", "query")
    required = param.get("required", False)
    typ = param.get("type", "string")
    fmt = param.get("format")

    if loc == "body":
        schema = param.get("schema", {})
        tsp_type = swagger_type_to_tsp(schema, defs)
        return None, tsp_type

    tsp_type = "string"
    if typ == "integer":
        m = {"int64": "int64", "int32": "int32", "uint16": "uint16"}
        tsp_type = m.get(fmt, "int32") if fmt else "int32"
    elif typ == "boolean":
        tsp_type = "boolean"
    elif typ == "number":
        tsp_type = "float64"
    elif typ == "array":
        items = param.get("items", {})
        tsp_type = f"{swagger_type_to_tsp(items, defs)}[]"
    elif typ == "string":
        if "enum" in param:
            tsp_type = " | ".join(f'"{v}"' for v in param["enum"])
        elif fmt in ("binary", "byte"):
            tsp_type = "bytes"

    opt = "?" if not required else ""
    sn = safe_param(name)

    if loc == "query":
        if sn != name:
            dec = f'@query("{name}") '
        else:
            dec = "@query "
    elif loc == "header":
        dec = f'@header("{name}") '
    elif loc == "path":
        if sn != name:
            dec = f'@path("{name}") '
        else:
            dec = "@path "
    else:
        return None, None

    return f"{dec}{sn}{opt}: {tsp_type}", None


def generate_route_op(path, method, op, defs, used_op_names, all_model_names):
    lines = []
    op_id = op.get("operationId", f"{method}Op")
    # Avoid conflicts with model names
    if op_id in all_model_names:
        op_id = f"{op_id}Op"
    # Ensure unique op names
    if op_id in used_op_names:
        op_id = f"{op_id}_{method}"
    used_op_names.add(op_id)

    desc = op.get("summary", "")
    if desc:
        lines.append(format_doc(desc.strip()).rstrip())

    params = op.get("parameters", [])
    param_strs = []
    body_type = None

    for param in params:
        if "$ref" in param:
            continue
        result, extra = param_to_tsp(param, defs)
        if param.get("in") == "body":
            body_type = extra
        elif result:
            param_strs.append(result)

    responses = op.get("responses", {})
    response_type = "void"
    for code in [200, 201, "200", "201"]:
        if code in responses:
            resp = responses[code]
            schema = resp.get("schema", {})
            if schema:
                response_type = swagger_type_to_tsp(schema, defs)
            break

    if body_type:
        param_strs.append(f"@body body: {body_type}")

    dec = {"get": "@get", "post": "@post", "put": "@put", "delete": "@delete",
           "patch": "@patch", "head": "@head"}.get(method, f"@{method}")

    all_params = ", ".join(param_strs)
    lines.append(f'{dec}')
    lines.append(f'@route("{path}")')
    lines.append(f"op {op_id}({all_params}): {response_type};")
    lines.append("")
    return "\n".join(lines)


def generate_route_file(group_name, routes, defs, all_model_names):
    lines = ['import "@typespec/http";', 'import "@typespec/openapi";', ""]
    needed_groups = set()
    for path, methods in routes:
        for method, op in methods.items():
            refs = find_refs_in_schema(op)
            for ref in refs:
                if ref in MODEL_TO_GROUP:
                    needed_groups.add(MODEL_TO_GROUP[ref])
    for imp in sorted(needed_groups):
        lines.append(f'import "../models/{imp}.tsp";')
    if needed_groups:
        lines.append("")
    lines.append("using TypeSpec.Http;")
    lines.append("using TypeSpec.OpenAPI;")
    lines.append("")
    lines.append("namespace DockerEngine;")
    lines.append("")

    used_op_names = set()
    for path, methods in routes:
        for method in ("get", "post", "put", "delete", "patch", "head", "options"):
            if method in methods:
                lines.append(generate_route_op(path, method, methods[method], defs, used_op_names, all_model_names))
    return "\n".join(lines)


def main():
    with open("schemas/swagger-v2.yaml") as f:
        spec = yaml.safe_load(f)

    defs = spec.get("definitions", {})
    paths = spec.get("paths", {})

    all_assigned = set()
    for models in MODEL_GROUPS.values():
        all_assigned.update(models)
    unassigned = set(defs.keys()) - all_assigned
    if unassigned:
        print(f"Unassigned models: {unassigned}", file=sys.stderr)

    os.makedirs("models", exist_ok=True)
    for gname, mnames in MODEL_GROUPS.items():
        content = generate_model_file(gname, mnames, defs)
        fp = f"models/{gname}.tsp"
        with open(fp, "w") as f:
            f.write(content)
        print(f"  Generated {fp} ({len(mnames)} models)")

    os.makedirs("routes", exist_ok=True)
    route_groups = {g: [] for g in ROUTE_GROUPS}
    for path, methods in paths.items():
        group = classify_route(path)
        http_methods = {k: v for k, v in methods.items()
                       if k in ("get", "post", "put", "delete", "patch", "head", "options")}
        if http_methods:
            route_groups[group].append((path, http_methods))

    all_model_names = set(defs.keys())

    for gname, routes in route_groups.items():
        if not routes:
            continue
        content = generate_route_file(gname, routes, defs, all_model_names)
        fp = f"routes/{gname}.tsp"
        with open(fp, "w") as f:
            f.write(content)
        print(f"  Generated {fp} ({len(routes)} routes)")


if __name__ == "__main__":
    main()
