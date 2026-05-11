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
      @transformer = dependencies.fetch(:transformer) { Transformer.new(@config.max_payload_mb) }
      initialize_stdout(dependencies)
    end

    def initialize_stdout(dependencies)
      @stdout = dependencies.fetch(:stdout) { $stdout }
      @stdout.sync = true
    end

    def call(env)
      request = Rack::Request.new(env)
      started_at = current_time
      payload = initial_log_payload(request)

      with_error_handling(payload) do
        handle_request(request, payload, started_at)
      end
    end

    private

    def handle_request(request, payload, started_at)
      key_id = authenticate_request(request)
      policy_result = authorize_request(key_id, request)
      unless policy_result
        payload.merge!(key_id: key_id, allowed: false, error: 'policy.mismatch')
        return forbidden_response
      end

      response_status, response_headers, response_body = @forwarder.forward(
        request,
        query_allowed: policy_result[:query_allowed],
        allowed_request_headers: policy_result[:allowed_request_headers]
      )
      transformed_body = @transformer.apply(response_body.to_s, response_headers, policy_result[:transforms])
      response_headers['Content-Length'] = transformed_body.bytesize.to_s
      response_headers['Content-Type'] ||= 'application/json'

      payload.merge!(key_id: key_id,
                     allowed: true,
                     upstream_status: response_status,
                     duration_ms: elapsed_ms(started_at))

      [response_status, response_headers, [transformed_body]]
    end

    def with_error_handling(payload)
      response = yield
      log_event(payload)
      response
    rescue RateLimitedError => e
      record_error(payload, e)
      rate_limited_response(e.retry_after)
    rescue AuthenticationError => e
      record_error(payload, e)
      unauthorized_response
    rescue UpstreamError, ResponseSizeError => e
      record_error(payload, e)
      [502, { 'Content-Type' => 'application/json' }, [{ error: 'Bad Gateway' }.to_json]]
    rescue StandardError => e
      payload.merge!(allowed: false, error: 'internal.error')
      payload[:error_detail] = e.message if log_error_detail?
      log_event(payload)
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
      @policy.authorize(key_id, request.request_method, request.path, request.GET)
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
      @stdout.puts(JSON.generate(payload))
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
  end
end
