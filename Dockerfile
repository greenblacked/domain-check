# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/domain-check ./cmd/domain-check

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build --chown=nonroot:nonroot /out/domain-check /app/domain-check
USER nonroot:nonroot
EXPOSE 8080
ENV PORT=8080 APP_ENV=production
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 CMD ["/app/domain-check", "healthcheck"]
ENTRYPOINT ["/app/domain-check"]

