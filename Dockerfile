# SPDX-License-Identifier: AGPL-3.0-only
FROM python:3.15.2-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build
WORKDIR /source/center
# The build image supplies the HTTPS client and archive reader. The compiler
# comes only from the release pinned by center/toolchain.json.
RUN python - <<'PY'
from hashlib import file_digest
from shutil import copyfileobj
from tarfile import open as open_archive
from tempfile import TemporaryFile
from urllib.request import urlopen

url = "https://go.dev/dl/go1.27.4.linux-amd64.tar.gz"
expected = "7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840"
with TemporaryFile() as archive:
    with urlopen(url, timeout=60) as response:
        copyfileobj(response, archive)
    archive.seek(0)
    if file_digest(archive, "sha256").hexdigest() != expected:
        raise SystemExit("The Go archive SHA-256 differs from the pinned release.")
    archive.seek(0)
    with open_archive(fileobj=archive, mode="r:gz") as release:
        release.extractall("/usr/local", filter="data")
PY
ENV PATH="/usr/local/go/bin:${PATH}" GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOTELEMETRY=off
COPY center/ ./
ARG SOURCE_REVISION
ARG SOURCE_COMMIT
ARG SOURCE_DIRTY
ARG APP_VERSION
ARG BUILD_KIND
ARG BUILD_ID
ARG PIPELINE_RUN
ARG SOURCE_EPOCH
RUN test -n "$SOURCE_REVISION" && sha256sum go.mod go.sum > /tmp/center-modules.sha256 \
    && go mod download && go mod verify \
    && identity=github.com/ArcForges/Cloud/center/internal/buildinfo \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X $identity.appVersion=${APP_VERSION} -X $identity.sourceCommit=${SOURCE_COMMIT} -X $identity.sourceDirty=${SOURCE_DIRTY} -X $identity.buildKind=${BUILD_KIND} -X $identity.buildID=${BUILD_ID} -X $identity.pipelineRun=${PIPELINE_RUN} -X $identity.sourceEpoch=${SOURCE_EPOCH}" \
    -o /out/arcforges-center ./cmd/arcforges-center \
    && sha256sum --check --quiet /tmp/center-modules.sha256 && test -x /out/arcforges-center

FROM mcr.microsoft.com/dotnet/runtime-deps:11.0.0-resolute-chiseled@sha256:24534e1f18024d3f8026061537fa21ba424f46cc0cdab4297c5528937b1ae960
ARG SOURCE_REVISION=local
LABEL org.opencontainers.image.source="https://github.com/ArcForges/Cloud" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.revision="$SOURCE_REVISION"
WORKDIR /app
COPY --from=build /out/arcforges-center ./
COPY LICENSE ./LICENSE
COPY artifacts/image-notices/ ./notices/
USER $APP_UID
EXPOSE 8080 8081
ENTRYPOINT ["/app/arcforges-center"]
