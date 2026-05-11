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

  def test_rejects_invalid_token
    env = { 'HTTP_X_PROXY_TOKEN' => 'bad-token', 'REMOTE_ADDR' => '203.0.113.5' }

    error = assert_raises(Proxy::AuthenticationError) { @auth.authenticate(env) }
    assert_equal('Invalid token', error.message)
  end

  def test_does_not_trust_x_real_ip_without_trusted_proxy_cidrs
    config_struct = Struct.new(:proxy_keys, :allowed_ip_ranges, :trusted_proxy_cidrs)
    config = config_struct.new({ 'p' => 'tok' }, ['10.0.0.0/8'], [])
    github_ips = Object.new
    github_ips.define_singleton_method(:include?) { |_ip| false }
    auth = Proxy::Auth.new(config, github_ips)

    env = {
      'HTTP_X_PROXY_TOKEN' => 'tok',
      'HTTP_X_REAL_IP' => '10.0.0.5',
      'REMOTE_ADDR' => '198.51.100.42'
    }

    # REMOTE_ADDR is the source of truth → not in 10.0.0.0/8 → rejected
    assert_raises(Proxy::AuthenticationError) { auth.authenticate(env) }
  end

  def test_trusts_x_real_ip_only_from_configured_trusted_proxy
    config_struct = Struct.new(:proxy_keys, :allowed_ip_ranges, :trusted_proxy_cidrs)
    config = config_struct.new({ 'p' => 'tok' }, ['10.0.0.0/8'], ['127.0.0.1/32'])
    github_ips = Object.new
    github_ips.define_singleton_method(:include?) { |_ip| false }
    auth = Proxy::Auth.new(config, github_ips)

    env = {
      'HTTP_X_PROXY_TOKEN' => 'tok',
      'HTTP_X_REAL_IP' => '10.0.0.5',
      'REMOTE_ADDR' => '127.0.0.1'
    }

    assert_equal('p', auth.authenticate(env))
  end

  def test_parses_xff_walks_from_right_skipping_trusted
    config_struct = Struct.new(:proxy_keys, :allowed_ip_ranges, :trusted_proxy_cidrs)
    config = config_struct.new({ 'p' => 'tok' }, ['10.0.0.0/8'], ['127.0.0.1/32', '192.168.0.0/16'])
    github_ips = Object.new
    github_ips.define_singleton_method(:include?) { |_ip| false }
    auth = Proxy::Auth.new(config, github_ips)

    env = {
      'HTTP_X_PROXY_TOKEN' => 'tok',
      'HTTP_X_FORWARDED_FOR' => '10.0.0.7, 192.168.1.1',
      'REMOTE_ADDR' => '127.0.0.1'
    }

    # Walking right→left, 192.168.1.1 is trusted; next 10.0.0.7 is the real client and is allowed.
    assert_equal('p', auth.authenticate(env))
  end

  def test_parses_forwarded_header_rfc7239
    config_struct = Struct.new(:proxy_keys, :allowed_ip_ranges, :trusted_proxy_cidrs)
    config = config_struct.new({ 'p' => 'tok' }, ['10.0.0.0/8'], ['127.0.0.1/32'])
    github_ips = Object.new
    github_ips.define_singleton_method(:include?) { |_ip| false }
    auth = Proxy::Auth.new(config, github_ips)

    env = {
      'HTTP_X_PROXY_TOKEN' => 'tok',
      'HTTP_FORWARDED' => 'for=10.0.0.42;proto=https',
      'REMOTE_ADDR' => '127.0.0.1'
    }

    assert_equal('p', auth.authenticate(env))
  end
end
