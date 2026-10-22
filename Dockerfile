FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /advisory-triage ./cmd/advisory-triage

FROM alpine:3.22
RUN apk add --no-cache ca-certificates git \
    # The workspace is mounted with another owner, which git refuses by default.
    && git config --system --add safe.directory '*'
COPY --from=build /advisory-triage /usr/local/bin/advisory-triage
ENTRYPOINT ["advisory-triage"]
