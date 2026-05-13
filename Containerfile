# syntax=docker/dockerfile:1
# Build a minimal static image for the FortiSandbox API mock.
# The service speaks plain HTTP — TLS termination is expected upstream (nginx).

# Run the Go toolchain on the build host's native arch and cross-compile to
# TARGETPLATFORM. This avoids running `go build` under QEMU user emulation,
# which can crash the Go runtime (lfstack.push invalid packing) when the
# emulator maps memory outside Go's 48-bit pointer-packing assumption.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.24-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w" -o /out/fsa-mock ./cmd/fsa-mock

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fsa-mock /usr/local/bin/fsa-mock
ENV FSA_ADDR=:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/fsa-mock"]
