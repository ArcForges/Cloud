# Published Kotlin client integration

## Scope and findings

Review base: `07d0fe05c48f1276f6c1b851143811c8cec8f877`. This increment verifies the existing anonymous unary Hello service, not Android UI, authentication, streaming, or additional product APIs. Contracts and other repositories remain unchanged.

The bounded review covered the Worker router, C# endpoint, final Docker image, published client versions, candidate promotion, and live smoke. Findings collected before implementation:

1. Cloud consumes Contracts `1.0.0-ci.25.1` and has no Kotlin consumer. The published common release is now `1.0.0-ci.36.1`, including `contracts-connect-client` on Maven Central.
2. The ingress rejects binary `application/grpc-web` (which defaults to protobuf) and mixed-case media types. Both were reproduced on the deployed API. ASP.NET already returns `application/grpc-web`; consumers must accept that response.
3. The ingress overwrites every caller deadline with `10S`. Both an expired `0m` and an invalid timeout currently reach Hello and succeed. Its abort signal alone does not guarantee completion if the binding ignores cancellation or stalls after response headers.
4. Existing tests cover C# native gRPC and TypeScript gRPC-Web but do not establish Kotlin's `/api` path, protobuf framing, application status, or deadline compatibility with the actual image and deployment.

## Unified implementation

1. Pin C#, TypeScript, and a standalone JVM Kotlin verification application to the published release. Restore Kotlin only from Maven Central, with a pinned Gradle wrapper, strict dependency locks and checksums. No local Contracts sources or Maven-local fallback.
2. Normalize binary protobuf media types at ingress. Keep text, JSON, native gRPC and compressed requests outside this public Hello boundary. Preserve the existing exact `/api` allowlist and remove the prefix exactly once.
3. Validate gRPC timeout syntax; use the smaller of the caller budget and the ten-second Hello limit, measured from ingress through the complete unary response. Deduct time already spent reading the request. Return valid gRPC-Web status for malformed/expired deadlines; enforce cancellation independently of binding cooperation. Keep health bounded at fifteen seconds and body reads at five seconds. No automatic RPC retry.
4. Test the router's timeout, cancellation and failure behavior deterministically, including stalled response bodies. Test Kotlin client deadlines with an explicitly local fault fixture; this is separate from real server evidence. Use the published Kotlin SDK for successful, Unicode, whitespace, size-boundary and application-error calls against the real AOT image, after restart, through local Wrangler/Containers, and after deployment. Assert HTTP status, request/response Content-Type, `/api` path, trailers and source identity.
5. Gate candidate promotion on these checks. Main deployment runs Kotlin against the same deployed revision before release. Preserve evidence; update dependency automation, security analysis, and development instructions for the verification project. PRs have no deployment credentials.

## Closure conditions

- Source, strict restore, unit/fault checks, workflow validation, and final Linux Native AOT image tests pass.
- Real local Worker/Container integration passes in Linux CI; Windows-only tests are not substituted for it.
- The published Kotlin client calls the current live Hello successfully. New ingress behavior is verified locally and in PR CI; verification against the newly deployed revision occurs after merge.
- Evidence distinguishes local fault injection, actual Docker, local Worker runtime, and actual Cloudflare. No Android device or new deployment is claimed from JVM tests.
- A reviewed PR contains the implementation and reproducible commands. Validation findings lead only to corrections within this scope.

## Validation record

- Local Windows: strict NuGet/npm/Gradle restore, warning-free C# build, five C# tests, TypeScript lint/type checks, fifteen router tests, and two Kotlin deadline fault scenarios passed. Gradle wrapper JAR matched the official SHA-256; dependency audit and actionlint passed.
- The final Linux x64 Native AOT Docker image passed C# native gRPC, TypeScript gRPC-Web and published Kotlin gRPC-Web checks, including container restart. Image evidence is recorded under `artifacts/` and not committed.
- Published Kotlin `1.0.0-ci.36.1` called the actual `https://arcforges.com/api` deployment at `07d0fe05c48f1276f6c1b851143811c8cec8f877`. All six success/application-error calls, binary status checks, and duplicate-prefix HTTP 404 mapping passed. This is evidence for that deployed revision only.
- Linux CI must additionally run the real local Worker/Container gate. Main's post-deployment verification gates release on the new revision. No Android device, browser UI, or deployment of this PR has been claimed.
- Initial clean CI identified one missing Kotlin plugin BOM checksum (`kotlinx-coroutines-bom:1.8.0`). Regeneration with an empty Gradle cache added only that record; its SHA-256 was independently matched against Maven Central. Dependency versions and strict verification remain unchanged.

## Protocol references

- [gRPC-Web media types and trailers](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md)
- [gRPC timeout grammar](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
- [Connect-Kotlin errors and cancellation](https://connectrpc.com/docs/kotlin/errors/)
