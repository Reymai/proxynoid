# typed: true
# frozen_string_literal: true

module Proxy
  # Validates the structure of a parsed policies.yml hash.
  # Raises PolicyError with the yaml-path of the offending value when invalid.
  module PolicySchema
    HTTP_METHODS = %w[GET HEAD POST PUT PATCH DELETE OPTIONS].freeze

    ALLOWED_KEY_FIELDS = %w[description transforms allowed allowed_request_headers].freeze
    ALLOWED_RULE_FIELDS = %w[
      method path resource_ids query transforms allowed_request_headers
      require_signature upstream
    ].freeze
    ALLOWED_QUERY_FIELDS = %w[allowed required values].freeze
    ALLOWED_TRANSFORM_FIELDS = %w[response].freeze
    ALLOWED_RESPONSE_FIELDS = %w[mask_values].freeze
    ALLOWED_MASK_FIELDS = %w[keys key_patterns whitelist].freeze

    PATH_PATTERN = %r{\A/[A-Za-z0-9/_:.-]+\z}

    def self.validate!(raw)
      raise PolicyError, 'policy must be a hash' unless raw.is_a?(Hash)

      reject_unknown!(raw, %w[keys], path: 'root')
      keys = raw['keys'] || {}
      raise PolicyError, 'keys: must be a hash' unless keys.is_a?(Hash)

      keys.each do |key_id, key_config|
        validate_key!(key_id, key_config)
      end
    end

    def self.validate_key!(key_id, key_config)
      path = "keys.#{key_id}"
      raise PolicyError, "#{path}: must be a hash" unless key_config.is_a?(Hash)

      reject_unknown!(key_config, ALLOWED_KEY_FIELDS, path: path)
      validate_transforms!(key_config['transforms'], "#{path}.transforms") if key_config.key?('transforms')

      allowed = key_config['allowed']
      raise PolicyError, "#{path}.allowed: must be an array" if allowed && !allowed.is_a?(Array)

      Array(allowed).each_with_index do |rule, index|
        validate_rule!(rule, "#{path}.allowed[#{index}]")
      end
    end

    def self.validate_rule!(rule, path)
      raise PolicyError, "#{path}: must be a hash" unless rule.is_a?(Hash)

      reject_unknown!(rule, ALLOWED_RULE_FIELDS, path: path)
      validate_method!(rule['method'], "#{path}.method")
      validate_path!(rule['path'], "#{path}.path")
      validate_resource_ids!(rule['resource_ids'], "#{path}.resource_ids") if rule.key?('resource_ids')
      validate_query!(rule['query'], "#{path}.query") if rule.key?('query')
      validate_transforms!(rule['transforms'], "#{path}.transforms") if rule.key?('transforms')
      validate_upstream!(rule['upstream'], "#{path}.upstream") if rule.key?('upstream')
      validate_bool!(rule['require_signature'], "#{path}.require_signature") if rule.key?('require_signature')
    end

    def self.validate_method!(value, path)
      return if value.is_a?(String) && HTTP_METHODS.include?(value.upcase)

      raise PolicyError,
            "#{path}: must be one of #{HTTP_METHODS.join(', ')}"
    end

    def self.validate_path!(value, path)
      unless value.is_a?(String) && value.start_with?('/')
        raise PolicyError,
              "#{path}: must be a string starting with '/'"
      end
      raise PolicyError, "#{path}: contains invalid characters (#{value.inspect})" unless value.match?(PATH_PATTERN)
    end

    def self.validate_resource_ids!(value, path)
      return if value.nil?

      case value
      when Array
        value.each_with_index do |entry, index|
          raise PolicyError, "#{path}[#{index}]: must be a string" unless entry.is_a?(String) || entry.is_a?(Integer)
        end
      when Hash
        value.each do |param, allowed|
          raise PolicyError, "#{path}.#{param}: must be an array" unless allowed.is_a?(Array)
        end
      else
        raise PolicyError, "#{path}: must be an array (legacy) or hash"
      end
    end

    def self.validate_query!(value, path)
      raise PolicyError, "#{path}: must be a hash" unless value.is_a?(Hash)

      reject_unknown!(value, ALLOWED_QUERY_FIELDS, path: path)
      %w[allowed required].each do |field|
        next unless value.key?(field)
        raise PolicyError, "#{path}.#{field}: must be an array of strings" unless value[field].is_a?(Array)
      end

      values = value['values']
      return if values.nil?
      raise PolicyError, "#{path}.values: must be a hash" unless values.is_a?(Hash)

      values.each do |key, allowed|
        raise PolicyError, "#{path}.values.#{key}: must be an array" unless allowed.is_a?(Array)
      end
    end

    def self.validate_transforms!(value, path)
      return if value.nil?
      raise PolicyError, "#{path}: must be a hash" unless value.is_a?(Hash)

      reject_unknown!(value, ALLOWED_TRANSFORM_FIELDS, path: path)
      return unless value.key?('response')

      response = value['response']
      raise PolicyError, "#{path}.response: must be a hash" unless response.is_a?(Hash)

      reject_unknown!(response, ALLOWED_RESPONSE_FIELDS, path: "#{path}.response")
      mask = response['mask_values']
      return if mask.nil?
      raise PolicyError, "#{path}.response.mask_values: must be a hash" unless mask.is_a?(Hash)

      reject_unknown!(mask, ALLOWED_MASK_FIELDS, path: "#{path}.response.mask_values")
      validate_mask_values!(mask, "#{path}.response.mask_values")
    end

    def self.validate_mask_values!(mask, path)
      %w[keys key_patterns].each do |field|
        next unless mask.key?(field)
        raise PolicyError, "#{path}.#{field}: must be an array" unless mask[field].is_a?(Array)
      end

      whitelist = mask['whitelist']
      return if whitelist.nil? || whitelist.is_a?(Array)
      raise PolicyError, "#{path}.whitelist: must be an array or hash" unless whitelist.is_a?(Hash)

      whitelist.each do |key, allowed|
        raise PolicyError, "#{path}.whitelist.#{key}: must be an array" unless allowed.is_a?(Array)
      end
    end

    def self.validate_upstream!(value, path)
      raise PolicyError, "#{path}: must be an https URL" unless value.is_a?(String) && value.start_with?('https://')
    end

    def self.validate_bool!(value, path)
      return if [true, false].include?(value)

      raise PolicyError, "#{path}: must be true or false"
    end

    def self.reject_unknown!(hash, allowed, path:)
      unknown = hash.keys.map(&:to_s) - allowed
      return if unknown.empty?

      raise PolicyError, "#{path}: unknown fields: #{unknown.join(', ')}"
    end
  end
end
