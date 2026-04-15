# typed: true
# frozen_string_literal: true

require 'net/http'
require 'uri'

module Proxy
  class ResponseSizeError < StandardError; end unless const_defined?(:ResponseSizeError)

  class Forwarder
    def initialize(config)
      @config = config
    end

    def forward(request)
      uri = URI("https://api.digitalocean.com#{request.fullpath}")
      http_request = build_request(request, uri)
      http_request['Authorization'] = "Bearer #{@config.do_api_token}"
      apply_request_headers(http_request, request)

      response = perform_http_request(http_request, uri)
      [response.code.to_i, response.each_header.to_h, read_response_body(response)]
    end

    def perform_http_request(http_request, uri)
      Net::HTTP.start(uri.hostname, uri.port,
                      use_ssl: true,
                      open_timeout: @config.upstream_timeout,
                      read_timeout: @config.upstream_timeout) do |http|
        http.request(http_request)
      end
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

    def apply_request_headers(net_request, request)
      request.env.each do |key, value|
        next unless key.start_with?('HTTP_') || %w[CONTENT_TYPE CONTENT_LENGTH].include?(key)

        header_name = key.sub(/^HTTP_/, '').split('_').map(&:capitalize).join('-')
        next if %w[X-Proxy-Token Host Authorization].include?(header_name)

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
