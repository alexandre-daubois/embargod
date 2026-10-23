FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /securibot ./cmd/securibot

FROM alpine:3.22
RUN apk add --no-cache ca-certificates git \
    # The workspace is mounted with another owner, which git refuses by default.
    && git config --system --add safe.directory '*'
COPY --from=build /securibot /usr/local/bin/securibot
ENTRYPOINT ["securibot"]
