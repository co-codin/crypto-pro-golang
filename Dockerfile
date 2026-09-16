# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/crypto-pro ./cmd/crypto-pro

FROM alpine:3.20
RUN adduser -D -H -u 10001 app
COPY --from=build /out/crypto-pro /usr/local/bin/crypto-pro
COPY testdata/signatures /examples/signatures
COPY openapi/openapi.yaml /examples/openapi.yaml
USER app
EXPOSE 18080
ENV HTTP_ADDR=:18080 \
    CRYPTOPRO_SIGNATURE_VERIFY_ENABLED=1 \
    CRYPTOPRO_VERIFIER=synthetic \
    CRYPTOPRO_CRYPTCP_PATH=/opt/cprocsp/bin/amd64/cryptcp \
    CRYPTOPRO_PROCESS_TIMEOUT_SECONDS=30 \
    CRYPTOPRO_REQUEST_DEADLINE_SECONDS=45 \
    CRYPTOPRO_STALE_CRL_FALLBACK=0
ENTRYPOINT ["/usr/local/bin/crypto-pro"]
