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

- `DO_API_TOKEN` — master DigitalOcean API token. Required.
- `PROXY_KEYS` — JSON object mapping pipeline key IDs to secret tokens. Required.
- `ALLOWED_IP_RANGES` — optional comma-separated CIDR list for additional trusted source IPs.
- `MAX_PAYLOAD_MB` — optional maximum JSON payload size for upstream responses (default: `5`).
- `UPSTREAM_TIMEOUT` — optional DigitalOcean API request timeout in seconds (default: `10`).

Example:

```env
DO_API_TOKEN=your_master_digitalocean_token
PROXY_KEYS={"deploy_pipeline":"super-secure-token"}
ALLOWED_IP_RANGES=203.0.113.0/24,198.51.100.0/24
MAX_PAYLOAD_MB=5
UPSTREAM_TIMEOUT=10
```

### Policy file (`config/policies.yml`)

`config/policies.yml` defines pipelines and allowed API operations.

Example entry:

```yaml
keys:
  deploy_pipeline:
    description: "Staging Deployment Workflow"
    transforms:
      response:
        mask_values:
          whitelist: []
    allowed:
      - method: POST
        path: "/v2/apps/:app_id/deployments"
        resource_ids: ["abc-123-staging-id"]
      - method: GET
        path: "/v2/apps/:app_id/envs"
        resource_ids: ["abc-123-staging-id"]
        transforms:
          response:
            mask_values:
              whitelist: ["production", "staging", "us-east-1"]
```

#### Policy semantics

- `method` must match the HTTP method exactly.
- `path` may include dynamic segments like `:app_id`.
- `resource_ids` restrict matching to allowed resources.
- `transforms` controls response masking and filtering.

### Response masking

When configured, the proxy replaces fields named `value` with `[FILTERED]` unless the field value is allowed by the whitelist.

## Logging

Every request is logged to `stdout` in JSON form, including:

- `ts`
- `key_id`
- `source_ip`
- `method`
- `path`
- `allowed`
- `upstream_status`
- `duration_ms`

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
