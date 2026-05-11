# typed: true
# frozen_string_literal: true

module Proxy
  # In-process Prometheus metrics. Counters and one histogram, exposed via
  # Prometheus text format at /metrics. No gem dependency.
  class Metrics
    DURATION_BUCKETS_MS = [10, 50, 100, 250, 500, 1000, 2500, 5000].freeze

    OUTCOMES = %w[allowed denied auth_failed rate_limited upstream_error audit_only].freeze

    def initialize
      @mutex = Mutex.new
      @counters = Hash.new(0)
      @duration_buckets = Hash.new(0)
      @duration_sum_ms = 0.0
      @duration_count = 0
    end

    def increment_request(key_id:, method:, outcome:)
      key = [:requests, key_id.to_s, method.to_s.upcase, outcome.to_s]
      @mutex.synchronize { @counters[key] += 1 }
    end

    def observe_upstream_duration_ms(milliseconds)
      @mutex.synchronize do
        @duration_count += 1
        @duration_sum_ms += milliseconds
        DURATION_BUCKETS_MS.each do |bucket|
          @duration_buckets[bucket] += 1 if milliseconds <= bucket
        end
      end
    end

    def increment_github_refresh(result:)
      @mutex.synchronize { @counters[[:github_refresh, result.to_s]] += 1 }
    end

    def increment_policy_reload(result:)
      @mutex.synchronize { @counters[[:policy_reload, result.to_s]] += 1 }
    end

    def to_prometheus
      @mutex.synchronize { build_output }
    end

    private

    def build_output
      lines = []
      append_request_counters(lines)
      append_github_refresh(lines)
      append_policy_reload(lines)
      append_upstream_duration(lines)
      "#{lines.join("\n")}\n"
    end

    def append_request_counters(lines)
      lines << '# HELP proxynoid_requests_total Total proxy requests by outcome.'
      lines << '# TYPE proxynoid_requests_total counter'
      @counters.each do |key, value|
        next unless key[0] == :requests

        _, key_id, method, outcome = key
        lines << format('proxynoid_requests_total{key_id="%s",method="%s",outcome="%s"} %d',
                        escape(key_id), escape(method), escape(outcome), value)
      end
    end

    def append_github_refresh(lines)
      lines << '# HELP proxynoid_github_ip_refresh_total GitHub Actions IP range refresh attempts.'
      lines << '# TYPE proxynoid_github_ip_refresh_total counter'
      @counters.each do |key, value|
        next unless key[0] == :github_refresh

        lines << format('proxynoid_github_ip_refresh_total{result="%s"} %d', escape(key[1]), value)
      end
    end

    def append_policy_reload(lines)
      lines << '# HELP proxynoid_policy_reloads_total Policy reload attempts.'
      lines << '# TYPE proxynoid_policy_reloads_total counter'
      @counters.each do |key, value|
        next unless key[0] == :policy_reload

        lines << format('proxynoid_policy_reloads_total{result="%s"} %d', escape(key[1]), value)
      end
    end

    def append_upstream_duration(lines)
      lines << '# HELP proxynoid_upstream_duration_ms Time spent waiting on the upstream API in ms.'
      lines << '# TYPE proxynoid_upstream_duration_ms histogram'
      DURATION_BUCKETS_MS.each do |bucket|
        lines << format('proxynoid_upstream_duration_ms_bucket{le="%d"} %d', bucket, @duration_buckets[bucket])
      end
      lines << format('proxynoid_upstream_duration_ms_bucket{le="+Inf"} %d', @duration_count)
      lines << format('proxynoid_upstream_duration_ms_sum %.2f', @duration_sum_ms)
      lines << format('proxynoid_upstream_duration_ms_count %d', @duration_count)
    end

    def escape(value)
      value.to_s.gsub('\\', '\\\\').gsub('"', '\\"').gsub("\n", '\\n')
    end
  end
end
