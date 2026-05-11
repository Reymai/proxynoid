# typed: true
# frozen_string_literal: true

require 'json'
require_relative 'errors'

module Proxy
  class Transformer
    FILTERED_VALUE = '[FILTERED]'
    DEFAULT_SENSITIVE_KEYS = ['value'].freeze

    def initialize(max_payload_mb)
      @max_payload_bytes = max_payload_mb * 1024 * 1024
    end

    def apply(body, headers, transforms)
      return body unless should_transform?(headers, transforms)

      enforce_payload_size!(body)

      document = parse_json(body)
      return body unless document

      raw_config = transforms.dig('response', 'mask_values') || {}
      masked = mask_values(document, build_mask_config(raw_config))
      JSON.generate(masked)
    end

    private

    def should_transform?(headers, transforms)
      transforms.is_a?(Hash) && transforms.key?('response') && headers['content-type']&.include?('application/json')
    end

    def enforce_payload_size!(body)
      return if body.bytesize <= @max_payload_bytes

      raise ResponseSizeError, 'Payload exceeds configured MAX_PAYLOAD_MB'
    end

    def parse_json(body)
      JSON.parse(body)
    rescue JSON::ParserError
      nil
    end

    def build_mask_config(raw)
      keys = Array(raw['keys']).map(&:to_s).reject(&:empty?)
      keys = DEFAULT_SENSITIVE_KEYS.dup if keys.empty?
      patterns = Array(raw['key_patterns']).map { |pattern| compile_pattern(pattern) }.compact
      { keys: keys, patterns: patterns, whitelist: normalize_whitelist(raw['whitelist']) }
    end

    def compile_pattern(pattern)
      Regexp.new(pattern.to_s)
    rescue RegexpError
      nil
    end

    def normalize_whitelist(raw)
      case raw
      when Array then { 'value' => raw }
      when Hash then raw
      else {}
      end
    end

    def mask_values(document, config)
      case document
      when Hash
        document.each_with_object({}) do |(key, value), memo|
          memo[key] = if mask_key?(key, config)
                        whitelisted_or_filtered(key, value, config)
                      else
                        mask_values(value, config)
                      end
        end
      when Array
        document.map { |item| mask_values(item, config) }
      else
        document
      end
    end

    def mask_key?(key, config)
      return true if config[:keys].include?(key)

      config[:patterns].any? { |regex| regex.match?(key.to_s) }
    end

    def whitelisted_or_filtered(key, value, config)
      allowed = Array(config[:whitelist][key])
      allowed.include?(value) ? value : FILTERED_VALUE
    end
  end
end
