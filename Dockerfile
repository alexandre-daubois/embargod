FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /embargod ./cmd/embargod

FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
RUN apk add --no-cache ca-certificates git \
    # The workspace is mounted with another owner, which git refuses by default.
    && git config --system --add safe.directory '*'
COPY --from=build /embargod /usr/local/bin/embargod
ENTRYPOINT ["embargod"]
