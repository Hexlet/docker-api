import "@typespec/http";
import "@typespec/openapi";

import "./common.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

model Secret {
  ID?: string;
  Version?: ObjectVersion;
  CreatedAt?: utcDateTime;
  UpdatedAt?: utcDateTime;
  Spec?: SecretSpec;
}

model SecretSpec {
  /** User-defined name of the secret. */
  Name?: string;
  /** User-defined key/value metadata. */
  Labels?: Record<string>;
  /**
   * Data is the data to store as a secret, formatted as a standard base64-encoded
   * ([RFC 4648](https://tools.ietf.org/html/rfc4648#section-4)) string.
   * It must be empty if the Driver field is set, in which case the data is
   * loaded from an external secret store. The maximum allowed size is 500KB,
   * as defined in [MaxSecretSize](https://pkg.go.dev/github.com/moby/swarmkit/v2@v2.0.0/api/validation#MaxSecretSize).
   *
   * This field is only used to _create_ a secret, and is not returned by
   * other endpoints.
   */
  Data?: string;
  /**
   * Name of the secrets driver used to fetch the secret's value from an
   * external secret store.
   */
  Driver?: Driver;
  /**
   * Templating driver, if applicable
   *
   * Templating controls whether and how to evaluate the config payload as
   * a template. If no driver is set, no templating is used.
   */
  Templating?: Driver;
}
