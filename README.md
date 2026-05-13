# fsa-mock

A minimal, dependency-free Go mock of the FortiSandbox JSON-RPC API.

The service speaks **plain HTTP** — TLS termination is expected to be
handled by an upstream nginx. It exposes a single endpoint, `POST /jsonrpc`,
and routes operations by `params[0].url`. HTTP status is always `2xx`;
business errors are encoded in `result.status.code` / `message`, per the spec.

Module path: `github.com/bsv9/fsa-mock` · Go: `1.24`.

## Supported operations

| `params[0].url`                          | Behaviour                                                   |
| ---------------------------------------- | ----------------------------------------------------------- |
| `/sys/login/user`                        | Returns an opaque `session` token (or empty when creds set and wrong). |
| `/alert/ondemand/submit-file`            | Decodes base64 file, computes sha256/sha1/md5, returns a `sid`. |
| `/scan/result/get-jobs-of-submission`    | Returns one `jid` (`<sid>_0`) for the given `sid`.          |
| `/scan/result/job`                       | Returns a full `data` payload; verdict driven by sha256/md5. |

A file whose sha256 or md5 matches the configured bad-hash list is reported
as `rating: "Malicious"` (with `score`, `malware_name`, `category` either
from the matching entry or from the service defaults). Everything else is
reported as `rating: "Clean"`.

## Configuration

All configuration is via environment variables — no config file is required.

| Variable                | Default            | Purpose                                                              |
| ----------------------- | ------------------ | -------------------------------------------------------------------- |
| `FSA_ADDR`              | `:8080`            | Listen address.                                                      |
| `FSA_USER`              | _(unset)_          | Required username for `/sys/login/user`. Empty → any user accepted.  |
| `FSA_PASSWORD`          | _(unset)_          | Required password. Empty → any password accepted.                    |
| `FSA_BAD_HASHES`        | _(unset)_          | Comma-separated sha256 (64 hex) and/or md5 (32 hex) entries.         |
| `FSA_BAD_HASHES_FILE`   | _(unset)_          | JSON array of `BadHash` objects (`sha256`, `md5`, `malware_name`, `score`, `category`). |
| `FSA_MALWARE_NAME`      | `EICAR_TEST_FILE`  | Default `malware_name` when a bad-hash entry omits it.               |
| `FSA_SCORE`             | `90`               | Default `score` for malicious verdicts.                              |
| `FSA_CATEGORY`          | `Malware`          | Default `category` for malicious verdicts.                           |

Example `FSA_BAD_HASHES_FILE` content:

```json
[
  {
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "malware_name": "EICAR_TEST_FILE",
    "score": 100,
    "category": "Malware"
  }
]
```

## Running locally

```sh
make build
FSA_ADDR=:8080 ./bin/fsa-mock
```

Smoke test:

```sh
curl http://localhost:8080/healthz

curl -X POST http://localhost:8080/jsonrpc \
  -H 'Content-Type: application/json' \
  -d '{"method":"exec","params":[{"url":"/sys/login/user","user":"a","passwd":"b"}],"id":"1","version":"4.2.4"}'
```

## Container image

```sh
podman build -t ghcr.io/bsv9/fsa-mock:latest .
podman run --rm -p 8080:8080 ghcr.io/bsv9/fsa-mock:latest
```

The image is built from `gcr.io/distroless/static-debian12:nonroot` and
listens on `:8080` inside the container.

## Running under systemd (Podman Quadlet)

[Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
generates a regular systemd service from a `.container` file.

```sh
sudo cp deploy/fsa-mock.container /etc/containers/systemd/
sudo cp deploy/fsa-mock.env       /etc/fsa-mock.env
sudo systemctl daemon-reload
sudo systemctl start fsa-mock.service
sudo systemctl enable fsa-mock.service   # auto-start on boot
```


## Repository layout

```
cmd/fsa-mock/          entrypoint
internal/config/       environment-driven configuration
internal/store/        in-memory sid/jid mappings
internal/jsonrpc/      request/response envelopes
internal/server/       HTTP server and operation handlers
deploy/                Podman Quadlet unit + sample env file
Containerfile          OCI image definition
```

## Spec compliance notes

* HTTP responses are always `2xx`; failures are encoded in `result.status.code`.
* `result.status.code == 0` means success; any other code (with `status.message`)
  is treated as a business error by the client.
* The `md5` field is not returned in `/scan/result/job` because the client
  model does not parse it; sha256/md5 matching against the bad-hash list
  still happens internally on the bytes submitted.

## License

MIT