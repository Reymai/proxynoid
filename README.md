# proxynoid

A standalone Ruby HTTP proxy that enforces granular IAM-style access for GitHub Actions to the DigitalOcean API.

## Purpose

`proxynoid` removes the need to expose the master DigitalOcean API token inside CI. Each GitHub Actions workflow uses a static pipeline key (`X-Proxy-Token`), and the proxy enforces a strict allowlist of operations and resource access.

## How it works

1. GitHub Actions sends a request to the proxy with `X-Proxy-Token`.
2. The proxy validates the source IP against the current GitHub Actions CIDR ranges and any configured static IP ranges.
3. The proxy authenticates the pipeline key using constant-time comparison.
4. The request is authorized against `config/policies.yml`.
5. If allowed, the proxy forwards the request to the DigitalOcean API with `Authorization: Bearer $DO_API_TOKEN`.
6. The response is optionally transformed before returning to the client:
   - JSON payload size is limited by `MAX_PAYLOAD_MB`
   - `value` fields are masked unless whitelisted
7. The proxy logs each request event in JSON to `stdout` for auditing.

## Installation

1. Install dependencies:
   ```bash
   bundle install
   ```

2. Copy the example environment file and update values:
   ```bash
   cp .env.example .env
   ```

3. Set required environment variables in `.env`.

## Running

Start with the bundled server entrypoint:

```bash
bundle exec ruby bin/server
```

Or run via Rack:

```bash
bundle exec rackup config.ru -p 9292
```

## Configuration

### Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DO_API_TOKEN` | yes | — | Master DigitalOcean API token. Substituted into outbound `Authorization: Bearer …` so it never leaves the proxy host. |
| `PROXY_KEYS` | yes | — | JSON object mapping pipeline key IDs to their secret tokens, e.g. `{"deploy_pipeline":"…"}`. |
| `ALLOWED_IP_RANGES` | no | empty | Comma-separated CIDR list of additional trusted source IPs **in addition to** the live GitHub Actions ranges fetched from `api.github.com/meta`. Required when you run self-hosted runners. |
| `TRUSTED_PROXY_CIDRS` | no | empty | Comma-separated CIDRs of reverse proxies that may set `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, or RFC 7239 `Forwarded:`. If empty, `REMOTE_ADDR` is the only source of truth — header-based source IPs are never trusted, even from loopback. |
| `AUTH_FAILURE_RATE` | no | `10/60` | Token-bucket rate limit for failed auth attempts per source IP, written as `<burst>/<window-seconds>`. After the burst is exhausted, further attempts return `429` until the bucket refills. |
| `MAX_PAYLOAD_MB` | no | `5` | Maximum response body size returned from upstream. Larger payloads are dropped with `502`. |
| `UPSTREAM_TIMEOUT` | no | `10` | DigitalOcean API open/read timeout in seconds. |
| `LOG_ERROR_DETAIL` | no | unset | When `1`, the audit log adds an `error_detail` field with the raw exception message. Off by default so audit records stay free of upstream messages. |

Example:

```env
DO_API_TOKEN=your_master_digitalocean_token
PROXY_KEYS={"deploy_pipeline":"super-secure-token"}
ALLOWED_IP_RANGES=203.0.113.0/24,198.51.100.0/24
TRUSTED_PROXY_CIDRS=10.0.0.0/8
AUTH_FAILURE_RATE=10/60
MAX_PAYLOAD_MB=5
UPSTREAM_TIMEOUT=10
```

### Policy file (`config/policies.yml`)

`config/policies.yml` defines pipelines and the operations each pipeline is allowed to call. The file is validated at startup by `Proxy::PolicySchema` — unknown fields and typos are rejected loudly so a misnamed `methd:` never silently widens access.

Example:

```yaml
keys:
  deploy_pipeline:
    description: "Staging Deployment Workflow"
    transforms:
      response:
        mask_values:
          keys: [value]
          whitelist: []
    allowed:
      - method: POST
        path: "/v2/apps/:app_id/deployments"
        resource_ids:
          app_id: ["abc-123-staging-id"]
      - method: GET
        path: "/v2/apps/:app_id/envs"
        resource_ids:
          app_id: ["abc-123-staging-id"]
        query:
          allowed: [page, per_page]
          values:
            per_page: ["25", "50"]
        transforms:
          response:
            mask_values:
              keys: [value]
              key_patterns: ['(?i).*secret.*']
              whitelist:
                value: ["production", "staging", "us-east-1"]
```

#### Per-key fields

| Field | Type | Required | Purpose |
|---|---|---|---|
| `description` | string | no | Human-readable label shown in audit context. Not enforced. |
| `transforms` | hash | no | Default response transforms applied to every rule under this key. Per-rule transforms extend / restrict these. |
| `allowed` | array | yes | List of rules that requests must match. The first matching rule wins. |
| `allowed_request_headers` | array of strings | no | Extra inbound request headers (beyond the safe defaults) that may be forwarded upstream. Applied to every rule under this key. |

#### Per-rule fields

| Field | Type | Required | Purpose |
|---|---|---|---|
| `method` | string | yes | HTTP method. Compared case-insensitively against `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`. |
| `path` | string | yes | Path template. Must start with `/`. Use `:name` for dynamic segments (e.g. `/v2/apps/:app_id`). Allowed characters: `[A-Za-z0-9/_:.\-]`. |
| `resource_ids` | hash *or* array | no | Restricts the captured `:name` segments to a fixed set. **Hash form (preferred)** maps each path parameter to its allowed values, e.g. `{app_id: ["abc"], component: ["worker"]}` — every named param must match. **Array form (legacy)** matches against the first path parameter only and emits a deprecation warning at load. Omitting the field allows any value. |
| `query` | hash | no | Constrains query-string parameters. See below. |
| `transforms` | hash | no | Rule-level transforms merged on top of the key-level defaults. Whitelists intersect; new fields pass through. |
| `allowed_request_headers` | array of strings | no | Extra inbound request headers (beyond defaults) forwarded only for this rule. |

#### `query` reference

```yaml
query:
  allowed: [page, per_page]        # any other key in the request URL → 403
  required: [page]                 # request must include these keys
  values:
    per_page: ["10", "25", "50"]   # if the key is present, its value must be in the list
```

If `query` is omitted, the query string is forwarded unchanged. If `query.allowed` is set, the proxy *also* strips disallowed keys before forwarding (defense in depth) so a misconfigured upstream cannot see them.

#### `transforms.response.mask_values` reference

| Field | Type | Default | Purpose |
|---|---|---|---|
| `keys` | array of strings | `[value]` | Exact field names whose contents are replaced with `[FILTERED]`. |
| `key_patterns` | array of regex strings | `[]` | Field names matching any regex are also filtered (e.g. `'(?i).*secret.*'`). |
| `whitelist` | hash *or* array | `{}` | Per-field allowlist of values that bypass filtering. Hash form: `{value: ["production"], token: []}`. **Legacy array form** (`[…]`) is treated as the whitelist for the `value` field only. |

Behaviour on merge: when both key-level and rule-level whitelists specify the same field, the rule's list is *intersected* with the key's. Fields only present on one side pass through unchanged. Unknown field names in `whitelist` are accepted (they simply never match anything until added to `keys`).

#### Request headers

Only a safe default set of inbound headers is forwarded upstream: `Content-Type`, `Accept`, `User-Agent`, `Accept-Encoding`. Everything else — including `Authorization`, `Cookie`, `X-Forwarded-*`, `X-Real-IP`, `X-Client-IP`, and your own `X-Proxy-Token` — is stripped. Use `allowed_request_headers` (per-key or per-rule) to extend the allowlist for specific tracing or content-negotiation headers, e.g. `X-Trace-Id`.

### Source IP allowlist

The proxy refreshes the GitHub Actions CIDR list from `api.github.com/meta` every four hours; those ranges only cover **GitHub-hosted runners**. For self-hosted runners or other trusted CI workers, set `ALLOWED_IP_RANGES` — otherwise the proxy will reject your requests even with a valid token.

If your deployment puts a reverse proxy (LB, sidecar) in front of `proxynoid`, set `TRUSTED_PROXY_CIDRS` to its address range. Only then will `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, and RFC 7239 `Forwarded:` be honoured; the proxy walks `X-Forwarded-For` right-to-left, skipping trusted entries, to find the real client.

### Rotating pipeline keys

`PROXY_KEYS` may list as many active tokens as you need. The intended rotation flow is:

1. Add a new entry alongside the old one, e.g. `{"deploy_pipeline":"old","deploy_pipeline_v2":"new"}`.
2. Update the pipeline to send `deploy_pipeline_v2`'s token.
3. Once traffic for the old key has stopped, remove it on the next deploy.

Both tokens are checked in constant time; lookup order is irrelevant.

## Logging

Every request is logged to `stdout` as a single JSON line. Fields:

| Field | Always present | Meaning |
|---|---|---|
| `ts` | yes | ISO 8601 UTC timestamp |
| `source_ip` | yes | Resolved client IP after `TRUSTED_PROXY_CIDRS` walk |
| `method` | yes | HTTP method |
| `path` | yes | Request path (query string not included) |
| `key_id` | on auth success | Matched pipeline key ID |
| `allowed` | yes | Boolean — whether the request reached upstream |
| `upstream_status` | on allowed=true | Status code returned by DigitalOcean |
| `duration_ms` | on allowed=true | Wall-clock time spent on the upstream call |
| `error` | on allowed=false | Stable error code, see below |
| `error_detail` | only when `LOG_ERROR_DETAIL=1` | Free-text exception message — useful when debugging in non-prod |

### Error code taxonomy

| Code | Status | Meaning |
|---|---|---|
| `auth.ip_denied` | 401 | Source IP not in GitHub Actions ranges or `ALLOWED_IP_RANGES` |
| `auth.token_missing` | 401 | No `X-Proxy-Token` header |
| `auth.token_invalid` | 401 | Token present but does not match any entry in `PROXY_KEYS` |
| `auth.rate_limited` | 429 | Too many auth failures from this source IP; response includes `Retry-After` |
| `policy.mismatch` | 403 | Authenticated, but no rule in the matched pipeline accepts the (method, path, resource, query) combination |
| `upstream.size_exceeded` | 502 | Upstream response exceeded `MAX_PAYLOAD_MB` |
| `upstream.timeout` | 502 | DO API exceeded `UPSTREAM_TIMEOUT` |
| `upstream.error` | 502 | Other upstream network failure (DNS, TLS, refused, reset) |
| `internal.error` | 500 | Unexpected error inside the proxy itself |

## Security model

`proxynoid` defends against the following threats in CI environments:

- **Master-token leakage in CI logs** — `DO_API_TOKEN` is held only on the proxy host; pipeline workflows never see it.
- **Over-broad PATs** — even with a valid pipeline token, only the (method, path, resource, query) tuples listed in `policies.yml` are allowed.
- **Spoofed source IPs** — by default the proxy trusts only `REMOTE_ADDR`. Forwarded-IP headers must be explicitly enabled by listing your reverse proxy in `TRUSTED_PROXY_CIDRS`.
- **Audit-time secret leakage** — `transforms.response.mask_values` filters secret-bearing fields out of responses (e.g. DO app env `value` fields, configurable secret-key patterns) before they leave the proxy. With `LOG_ERROR_DETAIL` off, audit lines also stay clear of upstream payload bytes.
- **Online token brute force** — `AUTH_FAILURE_RATE` throttles failed auth attempts per source IP.

`proxynoid` does **not** defend against:

- Compromise of the proxy host itself (the master DO token lives there).
- Anything that the policy explicitly allows. Treat `config/policies.yml` as production configuration — review it like you would IAM.
- Outbound exfiltration from a compromised CI runner if the runner can reach the proxy and present a valid pipeline token. Combine with `resource_ids` and `query` constraints to make the blast radius small.

## Tests

Run the full test suite with:

```bash
bundle exec rake
```

Or run unit tests directly:

```bash
bundle exec ruby -Ilib test/*_test.rb
```

## Code quality

Run RuboCop style checks with:

```bash
bundle exec rubocop
```

Run Sorbet type checking with:

```bash
bundle exec srb tc
```

Regenerate the runtime gem RBI files explicitly when needed:

```bash
bundle exec bin/tapioca gem rack
```

If you add additional typed runtime gems later, regenerate their RBIs explicitly as well, for example:

```bash
bundle exec bin/tapioca gem puma
```
