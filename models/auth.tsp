import "@typespec/http";
import "@typespec/openapi";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

model AuthConfig {
  username?: string;
  password?: string;
  serveraddress?: string;
}

/** An identity token was generated successfully. */
model AuthResponse {
  /** The status of the authentication */
  Status: string;
  /** An opaque token used to authenticate a user after a successful login */
  IdentityToken?: string;
}
