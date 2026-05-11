# typed: true
# frozen_string_literal: true

require 'rack'
require 'json'
require 'time'
require_relative 'config'
require_relative 'auth'
require_relative 'github_ips'
require_relative 'policy'
require_relative 'forwarder'
require_relative 'transformer'
require_relative 'rate_limiter'
require_relative 'health'
require_relative 'audit_sink'
require_relative 'metrics'
require 'ipaddr'

module Proxy
  class Server
    def initialize(**dependencies)
      @config = dependencies.fetch(:config) { Config.load! }
      @github_ips = dependencies.fetch(:github_ips) { GithubIps.new(@config.allowed_ip_ranges) }
      @rate_limiter = dependencies.fetch(:rate_limiter) { RateLimiter.from_env(ENV.fetch('AUTH_FAILURE_RATE', nil)) }
      @auth = dependencies.fetch(:auth) { Auth.new(@config, @github_ips, rate_limiter: @rate_limiter) }
      @policy = dependencies.fetch(:policy, @config.policy)
      @forwarder = dependencies.fetch(:forwarder) { Forwarder.new(@config) }
      @transformer = dependencies.fetch(:transformer) { Transformer.new }
      @health = dependencies.fetch(:health) { Health.new(@github_ips) }
      @metrics = dependencies.fetch(:metrics) { Metrics.new }
      @metrics_token = dependencies.fetch(:metrics_token) { ENV.fetch('METRICS_TOKEN', nil) }
      @policy_mutex = Mutex.new
      initialize_audit_sink(dependencies)
      start_policy_watcher unless dependencies[:skip_policy_watcher]
    end

    def initialize_audit_sink(dependencies)
      @audit_sink = dependencies.fetch(:audit_sink) do
        AuditSink.new(stdout: dependencies.fetch(:stdout, $stdout),
                      webhook_url: ENV.fetch('AUDIT_WEBHOOK_URL', nil))
      end
    end

    def reload_policy!
      path = @config.respond_to?(:policy_path) ? @config.policy_path : nil
      return unless path && File.exist?(path)

      new_policy = Policy.load(path)
      rules = count_rules(new_policy)
      @policy_mutex.synchronize { @policy = new_policy }
      log_event(event: 'policy.reloaded', rules: rules, ts: time_stamp)
      @metrics.increment_policy_reload(result: 'success')
    rescue StandardError => e
      log_event(event: 'policy.reload_failed', error: e.message, ts: time_stamp)
      @metrics.increment_policy_reload(result: 'failure')
    end

    def call(env)
      request = Rack::Request.new(env)
      health_response = handle_health(request)
      return health_response if health_response

      started_at = current_time
      payload = initial_log_payload(request)

      with_error_handling(payload) do
        handle_request(request, payload, started_at)
      end
    end

    def handle_health(request)
      return nil unless request.get?

      case request.path
      when '/healthz' then @health.healthz
      when '/readyz' then @health.readyz
      when '/metrics' then metrics_response(request)
      end
    end

    def metrics_response(request)
      if @metrics_token && !valid_metrics_bearer?(request)
        return [401, { 'Content-Type' => 'application/json' }, [{ error: 'Unauthorized' }.to_json]]
      end

      [200, { 'Content-Type' => 'text/plain; version=0.0.4' }, [@metrics.to_prometheus]]
    end

    def valid_metrics_bearer?(request)
      header = request.get_header('HTTP_AUTHORIZATION').to_s
      return false unless header.start_with?('Bearer ')

      Rack::Utils.secure_compare(header.delete_prefix('Bearer ').strip, @metrics_token.to_s)
    rescue StandardError
      false
    end

    private

    def handle_request(request, payload, started_at)
      key_id = authenticate_request(request)
      policy_result = authorize_request(key_id, request)

      if policy_result.nil?
        return audit_only_passthrough(request, payload, started_at, key_id) if audit_only?

        payload.merge!(key_id: key_id, allowed: false, error: 'policy.mismatch')
        @metrics.increment_request(key_id: key_id.to_s, method: request.request_method, outcome: 'denied')
        return forbidden_response
      end

      forward_and_transform(request, policy_result, payload, started_at, key_id)
    end

    def forward_and_transform(request, policy_result, payload, started_at, key_id, would_deny: false)
      response_status, response_headers, response_body = @forwarder.forward(
        request,
        query_allowed: policy_result[:query_allowed],
        allowed_request_headers: policy_result[:allowed_request_headers]
      )
      transformed_body = @transformer.apply(response_body.to_s, response_headers, policy_result[:transforms])
      response_headers['Content-Length'] = transformed_body.bytesize.to_s
      response_headers['Content-Type'] ||= 'application/json'

      duration_ms = elapsed_ms(started_at)
      payload.merge!(key_id: key_id, allowed: true, upstream_status: response_status, duration_ms: duration_ms)
      payload[:would_deny] = true if would_deny
      payload[:audit_only_reason] = 'policy.mismatch' if would_deny
      record_request_metric(key_id, request, would_deny ? 'audit_only' : 'allowed', duration_ms)

      [response_status, response_headers, [transformed_body]]
    end

    def record_request_metric(key_id, request, outcome, duration_ms = nil)
      @metrics.increment_request(key_id: key_id.to_s, method: request.request_method, outcome: outcome)
      @metrics.observe_upstream_duration_ms(duration_ms) if duration_ms
    end

    def audit_only_passthrough(request, payload, started_at, key_id)
      forward_and_transform(request, passthrough_policy_result, payload, started_at, key_id, would_deny: true)
    end

    def passthrough_policy_result
      { transforms: {}, query_allowed: nil, allowed_request_headers: [] }
    end

    def audit_only?
      @config.respond_to?(:policy_audit_only) && @config.policy_audit_only
    end

    def with_error_handling(payload)
      response = yield
      log_event(payload)
      response
    rescue RateLimitedError => e
      record_error(payload, e)
      @metrics.increment_request(key_id: '', method: payload[:method].to_s, outcome: 'rate_limited')
      rate_limited_response(e.retry_after)
    rescue AuthenticationError => e
      record_error(payload, e)
      @metrics.increment_request(key_id: '', method: payload[:method].to_s, outcome: 'auth_failed')
      unauthorized_response
    rescue UpstreamError, ResponseSizeError => e
      record_error(payload, e)
      @metrics.increment_request(key_id: payload[:key_id].to_s, method: payload[:method].to_s,
                                 outcome: 'upstream_error')
      [502, { 'Content-Type' => 'application/json' }, [{ error: 'Bad Gateway' }.to_json]]
    rescue StandardError => e
      payload.merge!(allowed: false, error: 'internal.error')
      payload[:error_detail] = e.message if log_error_detail?
      log_event(payload)
      @metrics.increment_request(key_id: payload[:key_id].to_s, method: payload[:method].to_s,
                                 outcome: 'upstream_error')
      [500, { 'Content-Type' => 'application/json' }, [{ error: 'Internal Server Error' }.to_json]]
    end

    def record_error(payload, error)
      payload.merge!(allowed: false, error: error.code)
      payload[:error_detail] = error.message if log_error_detail?
      log_event(payload)
    end

    def log_error_detail?
      ENV['LOG_ERROR_DETAIL'] == '1'
    end

    def authenticate_request(request)
      @auth.authenticate(request.env)
    end

    def authorize_request(key_id, request)
      current_policy.authorize(key_id, request.request_method, request.path, request.GET)
    end

    def initial_log_payload(request)
      {
        ts: time_stamp,
        source_ip: request.ip,
        method: request.request_method,
        path: request.path
      }
    end

    def forbidden_response
      [403, { 'Content-Type' => 'application/json' }, [{ error: 'Forbidden' }.to_json]]
    end

    def unauthorized_response
      [401, { 'Content-Type' => 'application/json' }, [{ error: 'Unauthorized' }.to_json]]
    end

    def rate_limited_response(retry_after)
      [429, { 'Content-Type' => 'application/json', 'Retry-After' => retry_after.to_s },
       [{ error: 'Too Many Requests' }.to_json]]
    end

    def log_event(payload)
      @audit_sink.write(payload)
    end

    def current_time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def elapsed_ms(started_at)
      ((current_time - started_at) * 1000).round
    end

    def time_stamp
      Time.now.utc.iso8601
    end

    def start_policy_watcher
      interval = @config.respond_to?(:policy_reload_interval) ? @config.policy_reload_interval : 0
      path = @config.respond_to?(:policy_path) ? @config.policy_path : nil
      return if interval.nil? || interval.zero? || path.nil? || !File.exist?(path)

      @policy_watcher = Thread.new { policy_watch_loop(path, interval) }
      @policy_watcher.report_on_exception = true
    end

    def policy_watch_loop(path, interval)
      last_mtime = safe_mtime(path)
      loop do
        sleep interval
        current = safe_mtime(path)
        next if current.nil? || current == last_mtime

        last_mtime = current
        reload_policy!
      end
    rescue StandardError => e
      warn("[proxynoid] policy watcher crashed: #{e.class}: #{e.message}")
    end

    def safe_mtime(path)
      File.mtime(path)
    rescue StandardError
      nil
    end

    def count_rules(policy)
      keys = policy.instance_variable_get(:@keys) || {}
      keys.values.sum { |key_config| Array(key_config && key_config['allowed']).size }
    end

    def current_policy
      @policy_mutex.synchronize { @policy }
    end
  end
end
