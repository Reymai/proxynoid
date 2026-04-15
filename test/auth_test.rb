# frozen_string_literal: true

require_relative 'test_helper'

class AuthTest < Minitest::Test
  def setup
    config_struct = Struct.new(:proxy_keys, :allowed_ip_ranges)
    config = config_struct.new({ 'deploy_pipeline' => 'secret-token' }, ['203.0.113.0/24'])
    github_ips = Object.new
    github_ips.define_singleton_method(:include?) { |_ip| false }
    @auth = Proxy::Auth.new(config, github_ips)
  end

  def test_authenticates_valid_token_and_allowed_ip
    env = { 'HTTP_X_PROXY_TOKEN' => 'secret-token', 'REMOTE_ADDR' => '203.0.113.5' }
    assert_equal('deploy_pipeline', @auth.authenticate(env))
  end

  def test_rejects_missing_token
    env = { 'REMOTE_ADDR' => '203.0.113.5' }
    assert_raises(Proxy::AuthenticationError) { @auth.authenticate(env) }
  end

  def test_uses_request_ip_instead_of_first_forwarded_for
    env = {
      'HTTP_X_PROXY_TOKEN' => 'secret-token',
      'HTTP_X_FORWARDED_FOR' => '192.30.252.1, 203.0.113.5',
      'REMOTE_ADDR' => '203.0.113.5'
    }

    assert_equal('deploy_pipeline', @auth.authenticate(env))
  end

  def test_rejects_unallowed_ip
    env = { 'HTTP_X_PROXY_TOKEN' => 'secret-token', 'REMOTE_ADDR' => '198.51.100.10' }
    assert_raises(Proxy::AuthenticationError) { @auth.authenticate(env) }
  end
end
