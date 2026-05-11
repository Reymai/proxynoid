# typed: true
# frozen_string_literal: true

require 'net/http'
require 'openssl'
require 'socket'
require 'uri'
require_relative 'errors'

module Proxy
  class Forwarder
    DEFAULT_FORWARDED_HEADERS = %w[Content-Type Accept User-Agent Accept-Encoding].freeze

    def initialize(config)
      @config = config
    end

    def forward(request, query_allowed: nil, allowed_request_headers: nil)
      upstream_path = build_upstream_path(request, query_allowed)
      uri = URI("https://api.digitalocean.com#{upstream_path}")
      http_request = build_request(request, uri)
      http_request['Authorization'] = "Bearer #{@config.do_api_token}"
      apply_request_headers(http_request, request, allowed_request_headers)

      response = perform_http_request(http_request, uri)
      [response.code.to_i, response.each_header.to_h, read_response_body(response)]
    end

    def build_upstream_path(request, query_allowed)
      return request.fullpath if query_allowed.nil?
      return request.path if request.query_string.to_s.empty?

      kept = request.query_string.split('&').select do |pair|
        key = pair.split('=', 2).first.to_s
        base = key.sub(/\[.*\z/, '')
        decoded = ::Rack::Utils.unescape(base)
        query_allowed.include?(decoded)
      end

      kept.empty? ? request.path : "#{request.path}?#{kept.join('&')}"
    end

    def perform_http_request(http_request, uri)
      Net::HTTP.start(uri.hostname, uri.port,
                      use_ssl: true,
                      open_timeout: @config.upstream_timeout,
                      read_timeout: @config.upstream_timeout) do |http|
        http.request(http_request)
      end
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      raise UpstreamError.new("Upstream timed out: #{e.message}", code: 'upstream.timeout')
    rescue SocketError, IOError, Errno::ECONNREFUSED, Errno::ECONNRESET, OpenSSL::SSL::SSLError => e
      raise UpstreamError.new("Upstream connection failed: #{e.message}", code: 'upstream.error')
    end

    private

    def build_request(request, uri)
      method = request.request_method.upcase
      has_body = !%w[GET HEAD DELETE OPTIONS TRACE].include?(method)
      net_request = Net::HTTPGenericRequest.new(method, has_body, true, uri.request_uri)
      if has_body
        body = request.body.read
        net_request.body = body unless body.nil? || body.empty?
      end
      net_request
    end

    def apply_request_headers(net_request, request, extra_allowed)
      allowed = (DEFAULT_FORWARDED_HEADERS + Array(extra_allowed)).map(&:to_s).to_set(&:downcase)

      request.env.each do |key, value|
        next unless key.start_with?('HTTP_') || %w[CONTENT_TYPE CONTENT_LENGTH].include?(key)

        header_name = key.sub(/^HTTP_/, '').split('_').map(&:capitalize).join('-')
        next unless allowed.include?(header_name.downcase)

        net_request[header_name] = value
      end
    end

    def read_response_body(response)
      if response['content-length'] && !response['content-length'].empty?
        content_length = response['content-length'].to_i
        if content_length.positive? && content_length > max_payload_bytes
          raise ResponseSizeError, 'Payload exceeds configured MAX_PAYLOAD_MB'
        end
      end

      body = +''
      response.read_body do |chunk|
        body << chunk
        raise ResponseSizeError, 'Payload exceeds configured MAX_PAYLOAD_MB' if body.bytesize > max_payload_bytes
      end

      body
    end

    def max_payload_bytes
      @config.max_payload_mb * 1024 * 1024
    end
  end
end
