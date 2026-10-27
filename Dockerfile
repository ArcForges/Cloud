# SPDX-License-Identifier: AGPL-3.0-only
FROM mcr.microsoft.com/dotnet/sdk:10.0.401-noble-aot@sha256:96f3b7d45f53eb05990f05b89ce61c4e23d07a5098521c2f20b018630e34f298 AS build
WORKDIR /source
# Official Go archive is pinned and verified; no toolchain auto-download or mutable base tag.
RUN curl --fail --silent --show-error --location https://go.dev/dl/go1.27.3.linux-amd64.tar.gz -o /tmp/go.tar.gz \
    && echo "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}" GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOTELEMETRY=off
COPY global.json Directory.Build.props Directory.Build.targets Directory.Packages.props NuGet.Config ./
COPY src/ ./src/
RUN dotnet restore src/ArcForges.Cloud --locked-mode
COPY package-lock.json ./
COPY eng/version-sources.json ./eng/version-sources.json
ARG SOURCE_REVISION
ARG SOURCE_COMMIT
ARG SOURCE_DIRTY
ARG APP_VERSION
ARG BUILD_KIND
ARG BUILD_ID
ARG PIPELINE_RUN
ARG SOURCE_EPOCH
RUN test -n "$SOURCE_REVISION" && dotnet publish src/ArcForges.Cloud -c Release -r linux-x64 --no-restore \
    -p:CloudSourceArchive=true -p:SourceRevisionId="$SOURCE_COMMIT" -p:ArcForgesSourceCommit="$SOURCE_COMMIT" \
    -p:CloudSourceDirty="$SOURCE_DIRTY" -p:Version="$APP_VERSION" -p:ArcForgesBuildKind="$BUILD_KIND" \
    -p:ArcForgesBuildId="$BUILD_ID" -p:ArcForgesPipelineRun="$PIPELINE_RUN" -p:ArcForgesSourceDateEpoch="$SOURCE_EPOCH" \
    -o /out && test -x /out/ArcForges.Cloud
COPY hello-go/ ./hello-go/
WORKDIR /source/hello-go
RUN go mod download && go mod verify && go run ./tools/contractgen \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.appVersion=${APP_VERSION} -X main.sourceCommit=${SOURCE_COMMIT} -X main.sourceDirty=${SOURCE_DIRTY} -X main.buildKind=${BUILD_KIND} -X main.buildID=${BUILD_ID} -X main.pipelineRun=${PIPELINE_RUN} -X main.sourceEpoch=${SOURCE_EPOCH}" \
    -o /out/arcforges-hello-go ./cmd/server

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0.12-noble-chiseled@sha256:18d4848091a40d13dbfdd6a8340c1657dc3e2f2d7fa2f042e9d162e68669dbc9
ARG SOURCE_REVISION=local
LABEL org.opencontainers.image.source="https://github.com/ArcForges/Cloud" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.revision="$SOURCE_REVISION"
WORKDIR /app
COPY --from=build /out/ArcForges.Cloud ./
COPY --from=build /out/arcforges-hello-go ./
COPY LICENSE ./LICENSE
COPY artifacts/image-notices/ ./notices/
ENV ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
USER $APP_UID
EXPOSE 8080 8081
ENTRYPOINT ["/app/ArcForges.Cloud"]
