import "@typespec/http";
import "@typespec/openapi";

import "./common.tsp";
import "./containers.tsp";
import "./volumes.tsp";

using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace DockerEngine;

/** Information about an image in the local image cache. */
model ImageInspect {
  /**
   * ID is the content-addressable ID of an image.
   *
   * This identifier is a content-addressable digest calculated from the
   * image's configuration (which includes the digests of layers used by
   * the image).
   *
   * Note that this digest differs from the `RepoDigests` below, which
   * holds digests of image manifests that reference the image.
   */
  Id?: string;
  /**
   * Descriptor is an OCI descriptor of the image target.
   * In case of a multi-platform image, this descriptor points to the OCI index
   * or a manifest list.
   *
   * This field is only present if the daemon provides a multi-platform image store.
   *
   * WARNING: This is experimental and may change at any time without any backward
   * compatibility.
   */
  Descriptor?: OCIDescriptor | null;
  /**
   * Manifests is a list of image manifests available in this image. It
   * provides a more detailed view of the platform-specific image manifests or
   * other image-attached data like build attestations.
   *
   * Only available if the daemon provides a multi-platform image store
   * and the `manifests` option is set in the inspect request.
   *
   * WARNING: This is experimental and may change at any time without any backward
   * compatibility.
   */
  Manifests?: ImageManifestSummary[] | null;
  /**
   * Identity holds information about the identity and origin of the image.
   * This is trusted information verified by the daemon and cannot be modified
   * by tagging an image to a different name.
   */
  Identity?: Identity | null;
  /**
   * List of image names/tags in the local image cache that reference this
   * image.
   *
   * Multiple image tags can refer to the same image, and this list may be
   * empty if no tags reference the image, in which case the image is
   * "untagged", in which case it can still be referenced by its ID.
   */
  RepoTags?: string[];
  /**
   * List of content-addressable digests of locally available image manifests
   * that the image is referenced from. Multiple manifests can refer to the
   * same image.
   *
   * These digests are usually only available if the image was either pulled
   * from a registry, or if the image was pushed to a registry, which is when
   * the manifest is generated and its digest calculated.
   */
  RepoDigests?: string[];
  /** Optional message that was set when committing or importing the image. */
  Comment?: string | null;
  /**
   * Date and time at which the image was created, formatted in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   *
   * This information is only available if present in the image,
   * and omitted otherwise.
   */
  Created?: utcDateTime | null;
  /**
   * Name of the author that was specified when committing the image, or as
   * specified through MAINTAINER (deprecated) in the Dockerfile.
   */
  Author?: string | null;
  Config?: ImageConfig;
  /** Hardware CPU architecture that the image runs on. */
  Architecture?: string;
  /** CPU architecture variant (presently ARM-only). */
  Variant?: string | null;
  /** Operating System the image is built to run on. */
  Os?: string;
  /**
   * Operating System version the image is built to run on (especially
   * for Windows).
   */
  OsVersion?: string | null;
  /** Total size of the image including all layers it is composed of. */
  Size?: int64;
  GraphDriver?: DriverData | null;
  /** Information about the image's RootFS, including the layer IDs. */
  RootFS?: {
    Type: string;
    Layers?: string[];
  };
  /**
   * Additional metadata of the image in the local cache. This information
   * is local to the daemon, and not part of the image itself.
   */
  Metadata?: {
    LastTagTime?: utcDateTime | null;
  };
}

model ImageSummary {
  /**
   * ID is the content-addressable ID of an image.
   *
   * This identifier is a content-addressable digest calculated from the
   * image's configuration (which includes the digests of layers used by
   * the image).
   *
   * Note that this digest differs from the `RepoDigests` below, which
   * holds digests of image manifests that reference the image.
   */
  Id: string;
  /**
   * ID of the parent image.
   *
   * Depending on how the image was created, this field may be empty and
   * is only set for images that were built/created locally. This field
   * is empty if the image was pulled from an image registry.
   */
  ParentId: string;
  /**
   * List of image names/tags in the local image cache that reference this
   * image.
   *
   * Multiple image tags can refer to the same image, and this list may be
   * empty if no tags reference the image, in which case the image is
   * "untagged", in which case it can still be referenced by its ID.
   */
  RepoTags: string[];
  /**
   * List of content-addressable digests of locally available image manifests
   * that the image is referenced from. Multiple manifests can refer to the
   * same image.
   *
   * These digests are usually only available if the image was either pulled
   * from a registry, or if the image was pushed to a registry, which is when
   * the manifest is generated and its digest calculated.
   */
  RepoDigests: string[];
  /**
   * Date and time at which the image was created as a Unix timestamp
   * (number of seconds since EPOCH).
   */
  Created: int32;
  /** Total size of the image including all layers it is composed of. */
  Size: int64;
  /**
   * Total size of image layers that are shared between this image and other
   * images.
   *
   * This size is not calculated by default. `-1` indicates that the value
   * has not been set / calculated.
   */
  SharedSize: int64;
  /** User-defined key/value metadata. */
  Labels: Record<string>;
  /**
   * Number of containers using this image. Includes both stopped and running
   * containers.
   *
   * `-1` indicates that the value has not been set / calculated.
   */
  Containers: int32;
  /**
   * Manifests is a list of manifests available in this image.
   * It provides a more detailed view of the platform-specific image manifests
   * or other image-attached data like build attestations.
   *
   * WARNING: This is experimental and may change at any time without any backward
   * compatibility.
   */
  Manifests?: ImageManifestSummary[];
  /**
   * Descriptor is an OCI descriptor of the image target.
   * In case of a multi-platform image, this descriptor points to the OCI index
   * or a manifest list.
   *
   * This field is only present if the daemon provides a multi-platform image store.
   *
   * WARNING: This is experimental and may change at any time without any backward
   * compatibility.
   */
  Descriptor?: OCIDescriptor | null;
}

/** individual image layer information in response to ImageHistory operation */
model ImageHistoryResponseItem {
  Id: string;
  Created: int64;
  CreatedBy: string;
  Tags: string[];
  Size: int64;
  Comment: string;
}

model ImageDeleteResponseItem {
  /** The image ID of an image that was untagged */
  Untagged?: string;
  /** The image ID of an image that was deleted */
  Deleted?: string;
}

/** represents system data usage for image resources. */
model ImagesDiskUsage {
  /** Count of active images. */
  ActiveCount?: int64;
  /** Count of all images. */
  TotalCount?: int64;
  /** Disk space that can be reclaimed by removing unused images. */
  Reclaimable?: int64;
  /** Disk space in use by images. */
  TotalSize?: int64;
  /** List of image summaries. */
  Items?: unknown[];
}

/**
 * Identity holds information about the identity and origin of the image.
 * This is trusted information verified by the daemon and cannot be modified
 * by tagging an image to a different name.
 */
model Identity {
  /** Signature contains the properties of verified signatures for the image. */
  Signature?: SignatureIdentity[];
  /**
   * Pull contains remote location information if image was created via pull.
   * If image was pulled via mirror, this contains the original repository location.
   * After successful push this images also contains the pushed repository location.
   */
  Pull?: PullIdentity[];
  /** Build contains build reference information if image was created via build. */
  Build?: BuildIdentity[];
}

/**
 * BuildIdentity contains build reference information if image was created via build.
 */
model BuildIdentity {
  /**
   * Ref is the identifier for the build request. This reference can be used to
   * look up the build details in BuildKit history API.
   */
  Ref?: string;
  /** CreatedAt is the time when the build ran. */
  CreatedAt?: utcDateTime;
}

/**
 * PullIdentity contains remote location information if image was created via pull.
 * If image was pulled via mirror, this contains the original repository location.
 */
model PullIdentity {
  /** Repository is the remote repository location the image was pulled from. */
  Repository?: string;
}

/** SignatureIdentity contains the properties of verified signatures for the image. */
model SignatureIdentity {
  /** Name is a textual description summarizing the type of signature. */
  Name?: string;
  /** Timestamps contains a list of verified signed timestamps for the signature. */
  Timestamps?: SignatureTimestamp[];
  /**
   * KnownSigner is an identifier for a special signer identity that is known to the implementation.
   */
  KnownSigner?: KnownSignerIdentity;
  /**
   * DockerReference is the Docker image reference associated with the signature.
   * This is an optional field only present in older hashedrecord signatures.
   */
  DockerReference?: string;
  /**
   * Signer contains information about the signer certificate used to sign the image.
   */
  Signer?: SignerIdentity;
  /**
   * SignatureType is the type of signature format. E.g. "bundle-v0.3" or "hashedrecord".
   */
  SignatureType?: SignatureType;
  /**
   * Error contains error information if signature verification failed.
   * Other fields will be empty in this case.
   */
  Error?: string;
  /**
   * Warnings contains any warnings that occurred during signature verification.
   * For example, if there was no internet connectivity and cached trust roots were used.
   * Warning does not indicate a failed verification but may point to configuration issues.
   */
  Warnings?: string[];
}

/**
 * SignatureTimestamp contains information about a verified signed timestamp for an image signature.
 */
model SignatureTimestamp {
  Type?: SignatureTimestampType;
  URI?: string;
  Timestamp?: utcDateTime;
}

/** SignatureTimestampType is the type of timestamp used in the signature. */
union SignatureTimestampType {
  "Tlog",
  "TimestampAuthority",
}

/** SignatureType is the type of signature format. */
union SignatureType {
  "bundle-v0.3",
  "simplesigning-v1",
}

/**
 * KnownSignerIdentity is an identifier for a special signer identity that is known to the implementation.
 */
union KnownSignerIdentity {
  "DHI",
}

/**
 * SignerIdentity contains information about the signer certificate used to sign the image.
 */
model SignerIdentity {
  /** CertificateIssuer is the certificate issuer. */
  CertificateIssuer?: string;
  /** SubjectAlternativeName is the certificate subject alternative name. */
  SubjectAlternativeName?: string;
  /**
   * The OIDC issuer. Should match `iss` claim of ID token or, in the case of
   * a federated login like Dex it should match the issuer URL of the
   * upstream issuer. The issuer is not set the extensions are invalid and
   * will fail to render.
   */
  Issuer?: string;
  /** Reference to specific build instructions that are responsible for signing. */
  BuildSignerURI?: string;
  /**
   * Immutable reference to the specific version of the build instructions that is responsible for signing.
   */
  BuildSignerDigest?: string;
  /**
   * Specifies whether the build took place in platform-hosted cloud infrastructure or customer/self-hosted infrastructure.
   */
  RunnerEnvironment?: string;
  /** Source repository URL that the build was based on. */
  SourceRepositoryURI?: string;
  /**
   * Immutable reference to a specific version of the source code that the build was based upon.
   */
  SourceRepositoryDigest?: string;
  /** Source Repository Ref that the build run was based upon. */
  SourceRepositoryRef?: string;
  /** Immutable identifier for the source repository the workflow was based upon. */
  SourceRepositoryIdentifier?: string;
  /**
   * Source repository owner URL of the owner of the source repository that the build was based on.
   */
  SourceRepositoryOwnerURI?: string;
  /**
   * Immutable identifier for the owner of the source repository that the workflow was based upon.
   */
  SourceRepositoryOwnerIdentifier?: string;
  /** Build Config URL to the top-level/initiating build instructions. */
  BuildConfigURI?: string;
  /**
   * Immutable reference to the specific version of the top-level/initiating build instructions.
   */
  BuildConfigDigest?: string;
  /** Event or action that initiated the build. */
  BuildTrigger?: string;
  /** Run Invocation URL to uniquely identify the build execution. */
  RunInvocationURI?: string;
  /** Source repository visibility at the time of signing the certificate. */
  SourceRepositoryVisibilityAtSigning?: string;
}

model BuildInfo {
  id?: string;
  stream?: string;
  errorDetail?: ErrorDetail;
  status?: string;
  progressDetail?: ProgressDetail;
  aux?: ImageID;
}

/** BuildCache contains information about a build cache record. */
model BuildCache {
  /** Unique ID of the build cache record. */
  ID?: string;
  /** List of parent build cache record IDs. */
  Parents?: string[] | null;
  /** Cache record type. */
  Type?: "internal" | "frontend" | "source.local" | "source.git.checkout" | "exec.cachemount" | "regular";
  /** Description of the build-step that produced the build cache. */
  Description?: string;
  /** Indicates if the build cache is in use. */
  InUse?: boolean;
  /** Indicates if the build cache is shared. */
  Shared?: boolean;
  /** Amount of disk space used by the build cache (in bytes). */
  Size?: int32;
  /**
   * Date and time at which the build cache was created in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  CreatedAt?: utcDateTime;
  /**
   * Date and time at which the build cache was last used in
   * [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
   */
  LastUsedAt?: utcDateTime | null;
  UsageCount?: int32;
}

/** represents system data usage for build cache resources. */
model BuildCacheDiskUsage {
  /** Count of active build cache records. */
  ActiveCount?: int64;
  /** Count of all build cache records. */
  TotalCount?: int64;
  /** Disk space that can be reclaimed by removing inactive build cache records. */
  Reclaimable?: int64;
  /** Disk space in use by build cache records. */
  TotalSize?: int64;
  /** List of build cache records. */
  Items?: unknown[];
}

/** Image ID or Digest */
model ImageID {
  ID?: string;
}

model CreateImageInfo {
  id?: string;
  errorDetail?: ErrorDetail;
  status?: string;
  progressDetail?: ProgressDetail;
}

model PushImageInfo {
  errorDetail?: ErrorDetail;
  status?: string;
  progressDetail?: ProgressDetail;
}

/**
 * A descriptor struct containing digest, media type, and size, as defined in
 * the [OCI Content Descriptors Specification](https://github.com/opencontainers/image-spec/blob/v1.0.1/descriptor.md).
 */
model OCIDescriptor {
  /** The media type of the object this schema refers to. */
  mediaType?: string;
  /** The digest of the targeted content. */
  digest?: string;
  /** The size in bytes of the blob. */
  size?: int64;
  /** List of URLs from which this object MAY be downloaded. */
  urls?: string[] | null;
  /** Arbitrary metadata relating to the targeted content. */
  annotations?: Record<string> | null;
  /**
   * Data is an embedding of the targeted content. This is encoded as a base64
   * string when marshalled to JSON (automatically, by encoding/json). If
   * present, Data can be used directly to avoid fetching the targeted content.
   */
  data?: string | null;
  platform?: OCIPlatform;
  /** ArtifactType is the IANA media type of this artifact. */
  artifactType?: string | null;
}

/**
 * Describes the platform which the image in the manifest runs on, as defined
 * in the [OCI Image Index Specification](https://github.com/opencontainers/image-spec/blob/v1.0.1/image-index.md).
 */
model OCIPlatform {
  /** The CPU architecture, for example `amd64` or `ppc64`. */
  architecture?: string;
  /** The operating system, for example `linux` or `windows`. */
  os?: string;
  /**
   * Optional field specifying the operating system version, for example on
   * Windows `10.0.19041.1165`.
   */
  @encodedName("application/json", "os.version")
  os_version?: string;
  /**
   * Optional field specifying an array of strings, each listing a required
   * OS feature (for example on Windows `win32k`).
   */
  @encodedName("application/json", "os.features")
  os_features?: string[];
  /**
   * Optional field specifying a variant of the CPU, for example `v7` to
   * specify ARMv7 when architecture is `arm`.
   */
  variant?: string;
}

/** ImageManifestSummary represents a summary of an image manifest. */
model ImageManifestSummary {
  /**
   * ID is the content-addressable ID of an image and is the same as the
   * digest of the image manifest.
   */
  ID: string;
  Descriptor: OCIDescriptor;
  /**
   * Indicates whether all the child content (image config, layers) is fully available locally.
   */
  Available: boolean;
  Size: {
    Total: int64;
    Content: int64;
  };
  /**
   * The kind of the manifest.
   *
   * kind         | description
   * -------------|-----------------------------------------------------------
   * image        | Image manifest that can be used to start a container.
   * attestation  | Attestation manifest produced by the Buildkit builder for a specific image manifest.
   */
  Kind: "image" | "attestation" | "unknown";
  /**
   * The image data for the image manifest.
   * This field is only populated when Kind is "image".
   */
  ImageData?: {
    Platform: OCIPlatform;
    Containers: string[];
    Size: {
      Unpacked: int64;
    };
  } | null;
  /**
   * The image data for the attestation manifest.
   * This field is only populated when Kind is "attestation".
   */
  AttestationData?: {
    For: string;
  } | null;
}

/** Information about the storage used by the container. */
model Storage {
  /** Information about the storage used for the container's root filesystem. */
  RootFS?: RootFSStorage | null;
}

/** Information about the storage used for the container's root filesystem. */
model RootFSStorage {
  /** Information about the snapshot used for the container's root filesystem. */
  Snapshot?: RootFSStorageSnapshot | null;
}

/** Information about a snapshot backend of the container's root filesystem. */
model RootFSStorageSnapshot {
  /** Name of the snapshotter. */
  Name?: string;
}
