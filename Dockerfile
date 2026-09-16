# SPDX-License-Identifier: AGPL-3.0-only
FROM mcr.microsoft.com/dotnet/sdk:10.0.401-noble-aot@sha256:1a069a730888d278b5ac00e3e238707387d20d2b65f0fc6866b6180df0a767e0 AS build
WORKDIR /source
COPY global.json Directory.Build.props Directory.Packages.props NuGet.Config ./
COPY src/ArcForges.Cloud/ArcForges.Cloud.csproj src/ArcForges.Cloud/packages.lock.json ./src/ArcForges.Cloud/
RUN dotnet restore src/ArcForges.Cloud --locked-mode
COPY src/ArcForges.Cloud/ ./src/ArcForges.Cloud/
ARG SOURCE_REVISION=local
RUN test -n "$SOURCE_REVISION" && dotnet publish src/ArcForges.Cloud -c Release -r linux-x64 --no-restore -p:SourceRevisionId="$SOURCE_REVISION" -o /out && test -x /out/ArcForges.Cloud

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0.12-noble-chiseled@sha256:18d4848091a40d13dbfdd6a8340c1657dc3e2f2d7fa2f042e9d162e68669dbc9
ARG SOURCE_REVISION=local
LABEL org.opencontainers.image.source="https://github.com/ArcForges/Cloud" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.revision="$SOURCE_REVISION"
WORKDIR /app
COPY --from=build /out/ArcForges.Cloud ./
COPY LICENSE ./LICENSE
ENV ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
USER $APP_UID
EXPOSE 8080 8081
ENTRYPOINT ["/app/ArcForges.Cloud"]
