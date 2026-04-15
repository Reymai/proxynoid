# typed: true
# frozen_string_literal: true

require 'json'
require_relative 'errors'

module Proxy
  class Transformer
    FILTERED_VALUE = '[FILTERED]'

    def initialize(max_payload_mb)
      @max_payload_bytes = max_payload_mb * 1024 * 1024
    end

    def apply(body, headers, transforms)
      return body unless should_transform?(headers, transforms)

      enforce_payload_size!(body)

      document = parse_json(body)
      return body unless document

      masked = mask_values(document, transforms.dig('response', 'mask_values', 'whitelist') || [])
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

    def mask_values(document, whitelist)
      case document
      when Hash
        document.each_with_object({}) do |(key, value), memo|
          memo[key] = if key == 'value'
                        whitelist.include?(value) ? value : FILTERED_VALUE
                      else
                        mask_values(value, whitelist)
                      end
        end
      when Array
        document.map { |item| mask_values(item, whitelist) }
      else
        document
      end
    end
  end

  class ResponseSizeError < StandardError; end
end
