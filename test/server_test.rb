# frozen_string_literal: true

require 'tempfile'
require_relative 'test_helper'

class ServerTest < Minitest::Test
  def setup
    config_struct = Struct.new(:proxy_keys, :allowed_ip_ranges, :max_payload_mb, :upstream_timeout, :do_api_token,
                               :policy)
    @config = config_struct.new({ 'deploy_pipeline' => 'secret-token' }, [], 5, 10, 'do-token', nil)

    @github_ips = Object.new
    @github_ips.define_singleton_method(:include?) { |_ip| true }
    @github_ips.define_singleton_method(:ready?) { true }

    @auth = Proxy::Auth.new(@config, @github_ips)

    @policy = Object.new
    @policy.define_singleton_method(:authorize) do |key_id, method, path, _query = {}|
      return unless key_id == 'deploy_pipeline' && method == 'POST' && path == '/v2/apps/abc-123/deployments'

      { transforms: {}, query_allowed: nil }
    end

    @forwarder = Object.new
    @forwarder.define_singleton_method(:forward) do |_request, **_opts|
      [200, { 'content-type' => 'application/json' }, '{"ok":true}']
    end

    @transformer = Proxy::Transformer.new
    @server = Proxy::Server.new(config: @config, github_ips: @github_ips, auth: @auth, policy: @policy,
                                forwarder: @forwarder, transformer: @transformer)
  end

  def test_allows_authorized_request
    request = Rack::MockRequest.new(@server)
    response = request.post('/v2/apps/abc-123/deployments', 'HTTP_X_PROXY_TOKEN' => 'secret-token',
                                                            'REMOTE_ADDR' => '127.0.0.1', input: '{}')

    assert_equal 200, response.status
    assert_equal('{"ok":true}', response.body)
  end

  def test_rejects_missing_token
    request = Rack::MockRequest.new(@server)
    response = request.post('/v2/apps/abc-123/deployments', 'REMOTE_ADDR' => '127.0.0.1', input: '{}')

    assert_equal 401, response.status
  end

  def test_rejects_forbidden_path
    request = Rack::MockRequest.new(@server)
    response = request.post('/v2/apps/abc-123/other', 'HTTP_X_PROXY_TOKEN' => 'secret-token',
                                                      'REMOTE_ADDR' => '127.0.0.1', input: '{}')

    assert_equal 403, response.status
  end

  def test_forbidden_payload_logs_policy_mismatch
    logged_payload = nil
    @server.define_singleton_method(:log_event) do |payload|
      logged_payload = payload.dup
    end

    request = Rack::MockRequest.new(@server)
    request.post('/v2/apps/abc-123/other',
                 'HTTP_X_PROXY_TOKEN' => 'secret-token',
                 'REMOTE_ADDR' => '127.0.0.1',
                 input: '{}')

    assert_equal('deploy_pipeline', logged_payload[:key_id])
    assert_equal(false, logged_payload[:allowed])
    assert_equal('policy.mismatch', logged_payload[:error])
  end

  def test_logs_stable_error_code_on_invalid_token
    logged = nil
    @server.define_singleton_method(:log_event) { |payload| logged = payload.dup }

    request = Rack::MockRequest.new(@server)
    request.post('/v2/apps/abc-123/deployments',
                 'HTTP_X_PROXY_TOKEN' => 'wrong', 'REMOTE_ADDR' => '127.0.0.1', input: '{}')

    assert_equal('auth.token_invalid', logged[:error])
    refute logged.key?(:error_detail)
  end

  def test_logs_error_detail_when_env_flag_set
    ENV['LOG_ERROR_DETAIL'] = '1'
    logged = nil
    @server.define_singleton_method(:log_event) { |payload| logged = payload.dup }

    request = Rack::MockRequest.new(@server)
    request.post('/v2/apps/abc-123/deployments',
                 'HTTP_X_PROXY_TOKEN' => 'wrong', 'REMOTE_ADDR' => '127.0.0.1', input: '{}')

    assert_equal('auth.token_invalid', logged[:error])
    assert_equal('Invalid token', logged[:error_detail])
  ensure
    ENV.delete('LOG_ERROR_DETAIL')
  end

  def test_healthz_returns_200_without_auth
    request = Rack::MockRequest.new(@server)
    response = request.get('/healthz', 'REMOTE_ADDR' => '198.51.100.1')

    assert_equal 200, response.status
    assert_equal('ok', JSON.parse(response.body)['status'])
  end

  def test_readyz_returns_200_when_github_ips_ready
    request = Rack::MockRequest.new(@server)
    response = request.get('/readyz', 'REMOTE_ADDR' => '198.51.100.1')

    assert_equal 200, response.status
  end

  def test_readyz_returns_503_when_no_ranges_loaded
    not_ready = Object.new
    not_ready.define_singleton_method(:include?) { |_| false }
    not_ready.define_singleton_method(:ready?) { false }

    server = Proxy::Server.new(config: @config, github_ips: not_ready, auth: @auth, policy: @policy,
                               forwarder: @forwarder, transformer: @transformer,
                               health: Proxy::Health.new(not_ready))

    response = Rack::MockRequest.new(server).get('/readyz', 'REMOTE_ADDR' => '198.51.100.1')
    assert_equal 503, response.status
  end

  def test_reload_policy_swaps_in_a_fresh_policy_and_logs
    file = Tempfile.new(['policies', '.yml'])
    file.write(<<~YAML)
      keys:
        p:
          allowed:
            - method: GET
              path: "/v2/x"
    YAML
    file.close

    config_struct = Struct.new(:proxy_keys, :allowed_ip_ranges, :max_payload_mb, :upstream_timeout,
                               :do_api_token, :policy, :policy_path, :policy_reload_interval)
    cfg = config_struct.new({ 'p' => 't' }, [], 5, 10, 'do', nil, file.path, 0)

    server = Proxy::Server.new(config: cfg, github_ips: @github_ips, auth: @auth,
                               policy: @policy, forwarder: @forwarder, transformer: @transformer,
                               skip_policy_watcher: true)

    logged = []
    server.define_singleton_method(:log_event) { |payload| logged << payload }

    server.reload_policy!
    assert(logged.any? { |entry| entry[:event] == 'policy.reloaded' && entry[:rules] == 1 })
  ensure
    file&.unlink
  end

  def test_reload_policy_logs_failure_on_invalid_yaml
    file = Tempfile.new(['policies', '.yml'])
    file.write("keys:\n  p:\n    allowed:\n      - methd: GET\n        path: /x\n")
    file.close

    config_struct = Struct.new(:proxy_keys, :allowed_ip_ranges, :max_payload_mb, :upstream_timeout,
                               :do_api_token, :policy, :policy_path, :policy_reload_interval)
    cfg = config_struct.new({ 'p' => 't' }, [], 5, 10, 'do', nil, file.path, 0)

    server = Proxy::Server.new(config: cfg, github_ips: @github_ips, auth: @auth,
                               policy: @policy, forwarder: @forwarder, transformer: @transformer,
                               skip_policy_watcher: true)

    logged = []
    server.define_singleton_method(:log_event) { |payload| logged << payload }

    server.reload_policy!
    assert(logged.any? { |entry| entry[:event] == 'policy.reload_failed' })
  ensure
    file&.unlink
  end

  def test_health_endpoints_do_not_emit_audit_log
    logged = []
    @server.define_singleton_method(:log_event) { |payload| logged << payload }

    Rack::MockRequest.new(@server).get('/healthz')
    Rack::MockRequest.new(@server).get('/readyz')

    assert_empty logged
  end

  def test_returns_429_when_rate_limit_exceeded
    limiter = Proxy::RateLimiter.new(burst: 1, window_seconds: 60, clock: -> { 0.0 })
    auth = Proxy::Auth.new(@config, @github_ips, rate_limiter: limiter)
    server = Proxy::Server.new(config: @config, github_ips: @github_ips, auth: auth, policy: @policy,
                               forwarder: @forwarder, transformer: @transformer, rate_limiter: limiter)

    request = Rack::MockRequest.new(server)
    first = request.post('/v2/apps/abc-123/deployments',
                         'HTTP_X_PROXY_TOKEN' => 'wrong', 'REMOTE_ADDR' => '127.0.0.1', input: '{}')
    assert_equal 401, first.status

    second = request.post('/v2/apps/abc-123/deployments',
                          'HTTP_X_PROXY_TOKEN' => 'wrong', 'REMOTE_ADDR' => '127.0.0.1', input: '{}')
    assert_equal 429, second.status
    refute_nil second.headers['Retry-After']
  end

  def test_response_size_errors_return_bad_gateway
    forwarder = Object.new
    forwarder.define_singleton_method(:forward) do |_request, **_opts|
      raise Proxy::ResponseSizeError, 'Payload exceeds configured MAX_PAYLOAD_MB'
    end

    server = Proxy::Server.new(
      config: @config,
      github_ips: @github_ips,
      auth: @auth,
      policy: @policy,
      forwarder: forwarder,
      transformer: @transformer
    )
    request = Rack::MockRequest.new(server)
    response = request.post(
      '/v2/apps/abc-123/deployments',
      'HTTP_X_PROXY_TOKEN' => 'secret-token',
      'REMOTE_ADDR' => '127.0.0.1',
      input: '{}'
    )

    assert_equal 502, response.status
  end
end
