# typed: true
# frozen_string_literal: true

require 'json'
require 'psych'

module Proxy
  class ConfigError < StandardError; end
  class MissingEnv < ConfigError; end
  class InvalidEnv < ConfigError; end

  class Config
    attr_reader :do_api_token,
                :proxy_keys,
                :allowed_ip_ranges,
                :max_payload_mb,
                :upstream_timeout,
                :policy

    def self.load!
      new
    end

    def initialize
      @do_api_token = fetch_env!('DO_API_TOKEN')
      @proxy_keys = parse_proxy_keys(fetch_env!('PROXY_KEYS'))
      @allowed_ip_ranges = parse_allowed_ranges(ENV.fetch('ALLOWED_IP_RANGES', ''))
      @max_payload_mb = parse_positive_integer(ENV.fetch('MAX_PAYLOAD_MB', '5'), 'MAX_PAYLOAD_MB')
      @upstream_timeout = parse_positive_integer(ENV.fetch('UPSTREAM_TIMEOUT', '10'), 'UPSTREAM_TIMEOUT')
      @policy = Policy.load(File.expand_path('../../config/policies.yml', __dir__))
    end

    private

    def fetch_env!(name)
      value = ENV.fetch(name, nil)
      raise MissingEnv, "#{name} is required" if value.nil? || value.strip.empty?

      value
    end

    def parse_proxy_keys(value)
      parsed = JSON.parse(value)
      unless parsed.is_a?(Hash) && parsed.keys.all?(String)
        raise InvalidEnv, 'PROXY_KEYS must be a JSON object mapping key IDs to tokens'
      end

      parsed
    rescue JSON::ParserError => e
      raise InvalidEnv, "PROXY_KEYS is not valid JSON: #{e.message}"
    end

    def parse_allowed_ranges(value)
      value.split(',').map(&:strip).reject(&:empty?)
    end

    def parse_positive_integer(value, name)
      Integer(value).tap do |parsed|
        raise InvalidEnv, "#{name} must be greater than zero" unless parsed.positive?
      end
    rescue ArgumentError
      raise InvalidEnv, "#{name} must be an integer"
    end
  end
end
