# crypto-pro-golang

Standalone Go HTTP service that reimplements the Symfony `arb/crypto-pro`
CMS/CAdES signature-validation API. It is a small process with one domain
route, no database, no mail, and no application auth.

Compatible with `cognitive/crypto-validation-client` / `contract-backend`:

```text
VALIDATION_SERVICE_URL=http://<host>:18080/api/crypto/v1
```

The client appends `/validate`. `Authorization` (including a Bearer
`VALIDATION_PLATFORM_GUID`) is ignored. Restrict access at the network edge.

This repository does **not** include Kubernetes manifests, Helm charts,
licensed CryptoPro CSP archives, or credentials.

Canonical HTTP contract: [`openapi/openapi.yaml`](openapi/openapi.yaml).

## API contract

**`POST /api/crypto/v1/validate`** with `Content-Type: application/json`.

| Field | Rules |
| --- | --- |
| `type` | `attached` or `detached` |
| `format` | `bes` only |
| `sign` | Base64 CMS/CAdES. Whitespace is stripped; the remainder must be canonical Base64. Decoded size ≤ 12 MiB. |
| `file` | Required for `detached`, forbidden for `attached`. Base64 of the exact signed bytes, decoded size ≤ 10 MiB. |

JSON body ≤ 32 MiB. Extra fields are rejected.

Every application response sets **`X-Guid`** (UUID v4).

HTTP 200 means the check finished:

```json
{"isSignValid":true,"signInfo":{}}
```

```json
{"isSignValid":false,"error":{"code":"0x200001F9","message":"The signature is invalid."}}
```

Expected failures use the same mapping as the PHP responder:

| HTTP | When |
| --- | --- |
| 400 | Invalid JSON / Base64 / type / format / field combination / CMS structure |
| 502 | Provider or certificate-metadata error |
| 503 | Verification disabled, CSP unavailable, interrupted, or unsafe outcome |
| 504 | `cryptcp` exceeded the request deadline |

Verification is **off** unless `CRYPTOPRO_SIGNATURE_VERIFY_ENABLED=1`
(otherwise 503).

## Run with Docker Compose

Dev Compose uses the **synthetic** verifier: it extracts the embedded CMS
certificate and returns `isSignValid: true` with `signInfo`. No licensed CSP
is required.

```bash
docker compose up --build
```

The container listens on **port 18080** (`HTTP_ADDR=:18080`). Host mapping
is `18080:18080`.

```bash
curl --fail-with-body \
  --header 'Content-Type: application/json' \
  --data @testdata/signatures/attached.json \
  http://127.0.0.1:18080/api/crypto/v1/validate
```

```bash
curl --fail-with-body \
  --header 'Content-Type: application/json' \
  --data @testdata/signatures/detached.json \
  http://127.0.0.1:18080/api/crypto/v1/validate
```

Attached request:

```bash
curl --fail-with-body \
  --header 'Content-Type: application/json' \
  --data '{"type":"attached","format":"bes","sign":"<cms-base64>"}' \
  http://127.0.0.1:18080/api/crypto/v1/validate
```

Detached body:

```json
{
  "type": "detached",
  "format": "bes",
  "sign": "<cms-base64>",
  "file": "<exact-signed-bytes-base64>"
}
```

Without Docker:

```bash
CRYPTOPRO_SIGNATURE_VERIFY_ENABLED=1 \
CRYPTOPRO_VERIFIER=synthetic \
HTTP_ADDR=:18080 \
  go run ./cmd/crypto-pro
```

```bash
go test ./...
```

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `HTTP_ADDR` | `:18080` | Listen address (Compose publishes **18080**) |
| `CRYPTOPRO_SIGNATURE_VERIFY_ENABLED` | off | `1` / `true` / `yes` / `on` enables verification |
| `CRYPTOPRO_VERIFIER` | `cryptopro` | `synthetic` (dev) or `cryptopro` (real `cryptcp`) |
| `CRYPTOPRO_CRYPTCP_PATH` | `/opt/cprocsp/bin/amd64/cryptcp` | Path to `cryptcp` |
| `CRYPTOPRO_PROCESS_TIMEOUT_SECONDS` | `30` | Per-process timeout |
| `CRYPTOPRO_REQUEST_DEADLINE_SECONDS` | `45` | Deadline across all `cryptcp` calls in one request |
| `CRYPTOPRO_STALE_CRL_FALLBACK` | off | Retry with `-nochain -cadesbes` after `0x20000133` |

`contract-backend`:

```dotenv
VALIDATION_SERVICE_URL=http://<host>:18080/api/crypto/v1
VALIDATION_PLATFORM_GUID=<non-empty>
```

## Synthetic vs real cryptcp

| Mode | `CRYPTOPRO_VERIFIER` | What it does |
| --- | --- | --- |
| **Synthetic** (Compose default) | `synthetic` | Parses CMS, extracts the signer certificate, returns `signInfo`. Does not run CryptoPro. For local/dev only. |
| **CryptoPro** | `cryptopro` | Writes CMS (and detached content) into a private 0700 temp dir, extracts the cert, runs `cryptcp` with an argv array (no shell): `-verify -errchain -nonet -cadesbes`. Deletes the dir afterwards. |

Real-mode success is **exit 0** plus a single `[ErrorCode: 0x00000000]`.
An invalid signature is a **non-zero** exit plus a single
`[ErrorCode: 0x200001f9]`. Anything else is a service error.

This image does not contain CryptoPro. When you have an approved CSP runtime:

1. Provide `cryptcp` at `CRYPTOPRO_CRYPTCP_PATH` (mount or CSP base image —
   never commit the licensed archive).
2. Persist `/var/opt/cprocsp` so trusted roots, intermediates, and CRLs
   survive restarts. Verification is offline (`-nonet`).
3. Set `CRYPTOPRO_VERIFIER=cryptopro` and
   `CRYPTOPRO_SIGNATURE_VERIFY_ENABLED=1`.
4. Optionally set `CRYPTOPRO_STALE_CRL_FALLBACK=1` on stands with stale CRLs.

`certmgr` stays an operational tool. There is no HTTP API for it.

CMS bytes, certificates, temp paths, keys, PINs, and cryptcp stdout/stderr
are never logged.

## Package layout

```text
POST /api/crypto/v1/validate
        │
        ▼
internal/httpapi          HTTP boundary, X-Guid, JSON responder
        │
        ▼
internal/validate         request shape, Base64 rules, feature flag
        │
        ▼
domain.Verifier
        ├─ cryptopro.Verifier           real cryptcp
        └─ cryptopro.SyntheticVerifier  CMS extract only
```

| Package | Role |
| --- | --- |
| `cmd/crypto-pro` | `net/http` server |
| `cmd/fake-cryptcp` | Deterministic `cryptcp` double for tests |
| `internal/config` | Environment |
| `internal/domain` | Failures, `Result`, `Verifier` interface |
| `internal/validate` | Use-case + strict JSON request |
| `internal/cryptopro` | `cryptcp` driver, ErrorCode scanner, CMS extractor |
| `internal/httpapi` | Handler + responder |
| `internal/testsupport` | Test certificates and fake-cryptcp helper |
| `openapi/` | Canonical contract |
| `testdata/signatures/` | Sample attached / detached JSON |

There is **no Kubernetes or Helm** in this repository. Deploy with Docker
Compose or any process supervisor that can run the binary / image.

## Tests

`go test ./...` uses `cmd/fake-cryptcp` and does not need a licensed CSP.
Coverage includes attached/detached, strict Base64, `X-Guid`, failure mapping,
and the cryptcp argv / error-code contract.

## Secrets

Do not add employee certificates, private keys, PFX, PINs, `.env` files with
credentials, CSP installers, or raw provider output to this repository.
