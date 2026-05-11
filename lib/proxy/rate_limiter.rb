# typed: true
# frozen_string_literal: true

module Proxy
  # Token-bucket rate limiter for auth-failure throttling. Thread-safe, in-process.
  # One bucket per opaque key (typically the source IP). Successful auths leave
  # the bucket untouched; only failures consume a token.
  class RateLimiter
    DEFAULT_BURST = 10
    DEFAULT_WINDOW_SECONDS = 60

    def self.from_env(env_value)
      return new if env_value.nil? || env_value.strip.empty?

      burst_str, window_str = env_value.split('/', 2)
      burst = Integer(burst_str)
      window = Integer(window_str)
      raise ArgumentError, 'AUTH_FAILURE_RATE values must be positive' unless burst.positive? && window.positive?

      new(burst: burst, window_seconds: window)
    end

    def initialize(burst: DEFAULT_BURST, window_seconds: DEFAULT_WINDOW_SECONDS, clock: lambda {
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    })
      @burst = burst.to_f
      @refill_per_second = @burst / window_seconds.to_f
      @clock = clock
      @buckets = {}
      @mutex = Mutex.new
    end

    # Returns true when at least one token is currently available for `key`.
    # Does not consume — call record_failure on actual auth failure.
    def allow?(key)
      @mutex.synchronize { tokens_for(key) >= 1.0 }
    end

    # Consumes one token from the bucket for `key`. Returns the remaining count.
    def record_failure(key)
      @mutex.synchronize do
        current = tokens_for(key)
        new_value = [current - 1.0, 0.0].max
        @buckets[key] = [new_value, @clock.call]
        new_value
      end
    end

    # Seconds the caller should wait before retrying. Always >= 1 second.
    def retry_after_seconds
      [(1.0 / @refill_per_second).ceil, 1].max
    end

    private

    def tokens_for(key)
      tokens, last_seen = @buckets[key] || [@burst, @clock.call]
      now = @clock.call
      replenished = [tokens + ((now - last_seen) * @refill_per_second), @burst].min
      @buckets[key] = [replenished, now]
      replenished
    end
  end
end
