# frozen_string_literal: true

require_relative 'test_helper'

class ForwarderTest < Minitest::Test
  def setup
    WebMock.disable_net_connect!(allow_localhost: true)
    config_struct = Struct.new(:do_api_token, :upstream_timeout, :max_payload_mb)
    @config = config_struct.new('do-token', 10, 1)
    @forwarder = Proxy::Forwarder.new(@config)
  end

  def teardown
    WebMock.allow_net_connect!
  end

  def test_forwards_request_with_authorization_header_and_preserves_method
    stub_request(:post, 'https://api.digitalocean.com/v2/apps/abc/deployments')
      .with(headers: { 'Authorization' => 'Bearer do-token',
                       'Content-Type' => 'application/json' }, body: { 'foo' => 'bar' }.to_json)
      .to_return(status: 201, body: { success: true }.to_json, headers: { 'Content-Type' => 'application/json' })

    env = Rack::MockRequest.env_for(
      '/v2/apps/abc/deployments',
      method: 'POST',
      input: { foo: 'bar' }.to_json,
      'CONTENT_TYPE' => 'application/json',
      'HTTP_X_PROXY_TOKEN' => 'secret-token'
    )
    request = Rack::Request.new(env)

    status, headers, body = @forwarder.forward(request)

    assert_equal 201, status
    assert_equal({ 'content-type' => 'application/json' }, headers)
    assert_equal({ 'success' => true }.to_json, body)
  end

  def test_drops_non_whitelisted_request_headers
    stub_request(:get, 'https://api.digitalocean.com/v2/apps')
      .with do |req|
        !req.headers.keys.map(&:downcase).include?('x-evil') &&
          !req.headers.keys.map(&:downcase).include?('cookie') &&
          !req.headers.keys.map(&:downcase).include?('x-proxy-token')
      end
      .to_return(status: 200, body: '{}', headers: { 'Content-Type' => 'application/json' })

    env = Rack::MockRequest.env_for(
      '/v2/apps',
      method: 'GET',
      'HTTP_X_EVIL' => 'leak',
      'HTTP_COOKIE' => 'session=abc',
      'HTTP_X_PROXY_TOKEN' => 'secret',
      'HTTP_USER_AGENT' => 'test-agent'
    )
    request = Rack::Request.new(env)

    status, = @forwarder.forward(request)
    assert_equal 200, status
  end

  def test_forwards_extra_allowed_request_header
    stub_request(:get, 'https://api.digitalocean.com/v2/apps')
      .with(headers: { 'X-Trace-Id' => 'abc' })
      .to_return(status: 200, body: '{}', headers: { 'Content-Type' => 'application/json' })

    env = Rack::MockRequest.env_for('/v2/apps', method: 'GET', 'HTTP_X_TRACE_ID' => 'abc')
    request = Rack::Request.new(env)

    status, = @forwarder.forward(request, allowed_request_headers: ['X-Trace-Id'])
    assert_equal 200, status
  end

  def test_strips_disallowed_query_params_when_filter_set
    stub_request(:get, 'https://api.digitalocean.com/v2/apps')
      .with(query: { 'page' => '2' })
      .to_return(status: 200, body: '{}', headers: { 'Content-Type' => 'application/json' })

    env = Rack::MockRequest.env_for('/v2/apps?page=2&evil=1', method: 'GET')
    request = Rack::Request.new(env)

    status, = @forwarder.forward(request, query_allowed: ['page'])
    assert_equal 200, status
  end

  def test_passes_query_through_when_no_filter
    stub_request(:get, 'https://api.digitalocean.com/v2/apps')
      .with(query: { 'page' => '2', 'whatever' => '1' })
      .to_return(status: 200, body: '{}', headers: { 'Content-Type' => 'application/json' })

    env = Rack::MockRequest.env_for('/v2/apps?page=2&whatever=1', method: 'GET')
    request = Rack::Request.new(env)

    status, = @forwarder.forward(request)
    assert_equal 200, status
  end

  def test_rejects_upstream_payloads_over_max_size
    stub_request(:get, 'https://api.digitalocean.com/v2/apps/abc/deployments')
      .to_return(status: 200,
                 body: 'x' * (2 * 1024 * 1024),
                 headers: { 'Content-Type' => 'application/json', 'Content-Length' => (2 * 1024 * 1024).to_s })

    env = Rack::MockRequest.env_for('/v2/apps/abc/deployments', method: 'GET')
    request = Rack::Request.new(env)

    assert_raises(Proxy::ResponseSizeError) { @forwarder.forward(request) }
  end
end
