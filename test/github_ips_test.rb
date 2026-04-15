# frozen_string_literal: true

require_relative 'test_helper'

class GithubIpsTest < Minitest::Test
  def setup
    WebMock.disable_net_connect!(allow_localhost: true)
  end

  def teardown
    WebMock.allow_net_connect!
  end

  def test_includes_github_actions_cidr_ranges
    stub_request(:get, 'https://api.github.com/meta')
      .to_return(status: 200, body: { actions: ['192.30.252.0/22'] }.to_json)

    ips = Proxy::GithubIps.new(['203.0.113.0/24'])

    assert ips.include?('192.30.252.1')
    assert ips.include?('203.0.113.5')
    refute ips.include?('198.51.100.5')
  end

  def test_falls_back_to_static_ranges_when_github_fetch_fails
    stub_request(:get, 'https://api.github.com/meta').to_return(status: 500)

    ips = Proxy::GithubIps.new(['203.0.113.0/24'])

    assert ips.include?('203.0.113.42')
    refute ips.include?('192.30.252.1')
  end

  def test_retries_github_meta_fetch_when_transient_errors_occur
    stub_request(:get, 'https://api.github.com/meta')
      .to_return({ status: 503 }, { status: 503 }, { status: 200, body: { actions: ['192.30.252.0/22'] }.to_json })

    ips = Proxy::GithubIps.new(['203.0.113.0/24'])

    assert ips.include?('192.30.252.1')
  end

  def test_raises_when_initial_fetch_fails_and_no_static_ranges
    stub_request(:get, 'https://api.github.com/meta').to_return(status: 500)

    assert_raises(RuntimeError) do
      Proxy::GithubIps.new([])
    end
  end
end
