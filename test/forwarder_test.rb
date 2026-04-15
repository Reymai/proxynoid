# frozen_string_literal: true

require_relative 'test_helper'

class ForwarderTest < Minitest::Test
  def setup
    WebMock.disable_net_connect!(allow_localhost: true)
    config_struct = Struct.new(:do_api_token, :upstream_timeout)
    @config = config_struct.new('do-token', 10)
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
end
