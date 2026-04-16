# frozen_string_literal: true

require_relative 'test_helper'

class ServerTest < Minitest::Test
  def setup
    config_struct = Struct.new(:proxy_keys, :allowed_ip_ranges, :max_payload_mb, :upstream_timeout, :do_api_token,
                               :policy)
    @config = config_struct.new({ 'deploy_pipeline' => 'secret-token' }, [], 5, 10, 'do-token', nil)

    @github_ips = Object.new
    @github_ips.define_singleton_method(:include?) { |_ip| true }

    @auth = Proxy::Auth.new(@config, @github_ips)

    @policy = Object.new
    @policy.define_singleton_method(:authorize) do |key_id, method, path|
      return unless key_id == 'deploy_pipeline' && method == 'POST' && path == '/v2/apps/abc-123/deployments'

      { transforms: {} }
    end

    @forwarder = Object.new
    @forwarder.define_singleton_method(:forward) do |_request|
      [200, { 'content-type' => 'application/json' }, '{"ok":true}']
    end

    @transformer = Proxy::Transformer.new(5)
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
    assert_equal('policy_mismatch', logged_payload[:error])
  end

  def test_response_size_errors_return_bad_gateway
    forwarder = Object.new
    forwarder.define_singleton_method(:forward) do |_request|
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
