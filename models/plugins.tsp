import "@typespec/http";
import "@typespec/openapi";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** A plugin for the Engine API */
model Plugin {
  Id?: string;
  Name: string;
  /**
   * True if the plugin is running. False if the plugin is not running, only installed.
   */
  Enabled: boolean;
  /** user-configurable settings for the plugin. */
  Settings: {
    Mounts: PluginMount[];
    Env: string[];
    Args: string[];
    Devices: PluginDevice[];
  };
  /** plugin remote reference used to push/pull the plugin */
  PluginReference?: string;
  /** The config of a plugin. */
  Config: {
    Description: string;
    Documentation: string;
    `Interface`: {
      Types: string[];
      Socket: string;
      ProtocolScheme?: "" | "moby.plugins.http/v1";
    };
    Entrypoint: string[];
    WorkDir: string;
    User?: {
      UID?: uint32;
      GID?: uint32;
    };
    Network: {
      Type: string;
    };
    Linux: {
      Capabilities: string[];
      AllowAllDevices: boolean;
      Devices: PluginDevice[];
    };
    PropagatedMount: string;
    IpcHost: boolean;
    PidHost: boolean;
    Mounts: PluginMount[];
    Env: PluginEnv[];
    Args: {
      Name: string;
      Description: string;
      Settable: string[];
      Value: string[];
    };
    rootfs?: {
      type?: string;
      diff_ids?: string[];
    };
  };
}

model PluginMount {
  Name: string;
  Description: string;
  Settable: string[];
  Source: string;
  Destination: string;
  Type: string;
  Options: string[];
}

model PluginDevice {
  Name: string;
  Description: string;
  Settable: string[];
  Path: string;
}

model PluginEnv {
  Name: string;
  Description: string;
  Settable: string[];
  Value: string;
}

/**
 * Describes a permission the user has to accept upon installing
 * the plugin.
 */
model PluginPrivilege {
  Name?: string;
  Description?: string;
  Value?: string[];
}
