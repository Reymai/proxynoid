# frozen_string_literal: true

require_relative 'test_helper'
require_relative '../lib/proxy/rate_limiter'

class RateLimiterTest < Minitest::Test
  def setup
    @now = 0.0
    @clock = -> { @now }
  end

  def test_allows_until_burst_consumed
    limiter = Proxy::RateLimiter.new(burst: 3, window_seconds: 60, clock: @clock)

    3.times do
      assert limiter.allow?('ip-1')
      limiter.record_failure('ip-1')
    end

    refute limiter.allow?('ip-1')
  end

  def test_tokens_refill_over_time
    limiter = Proxy::RateLimiter.new(burst: 2, window_seconds: 60, clock: @clock)

    2.times do
      limiter.record_failure('ip-1')
    end

    refute limiter.allow?('ip-1')

    @now += 30 # 1 token regenerates (2 tokens / 60s * 30s = 1)
    assert limiter.allow?('ip-1')
  end

  def test_buckets_are_isolated_per_key
    limiter = Proxy::RateLimiter.new(burst: 1, window_seconds: 60, clock: @clock)

    limiter.record_failure('ip-1')
    refute limiter.allow?('ip-1')
    assert limiter.allow?('ip-2')
  end

  def test_from_env_parses_burst_and_window
    limiter = Proxy::RateLimiter.from_env('5/30')
    assert_instance_of Proxy::RateLimiter, limiter
  end

  def test_from_env_returns_default_when_blank
    assert_instance_of Proxy::RateLimiter, Proxy::RateLimiter.from_env(nil)
    assert_instance_of Proxy::RateLimiter, Proxy::RateLimiter.from_env('')
  end

  def test_retry_after_is_at_least_one_second
    limiter = Proxy::RateLimiter.new(burst: 100, window_seconds: 60, clock: @clock)
    assert_operator limiter.retry_after_seconds, :>=, 1
  end
end
