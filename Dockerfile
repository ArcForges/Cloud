# SPDX-License-Identifier: AGPL-3.0-only
FROM mcr.microsoft.com/dotnet/sdk:10.0.401-noble-aot@sha256:96f3b7d45f53eb05990f05b89ce61c4e23d07a5098521c2f20b018630e34f298 AS build
WORKDIR /source
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

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0.12-noble-chiseled@sha256:dc5cd0c7d0a39b825312b4f0986d99b9adf9b6a3af69bc23cd345c27d9ed916a
ARG SOURCE_REVISION=local
LABEL org.opencontainers.image.source="https://github.com/ArcForges/Cloud" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.revision="$SOURCE_REVISION"
WORKDIR /app
COPY --from=build /out/ArcForges.Cloud ./
COPY LICENSE ./LICENSE
COPY artifacts/image-notices/ ./notices/
ENV ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
USER $APP_UID
EXPOSE 8080 8081
ENTRYPOINT ["/app/ArcForges.Cloud"]
