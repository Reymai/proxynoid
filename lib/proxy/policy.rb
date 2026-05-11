# typed: true
# frozen_string_literal: true

require 'psych'
require_relative 'policy_schema'

module Proxy
  class Policy
    def self.load(path)
      raw = Psych.safe_load(File.read(path), symbolize_names: false) || {}
      PolicySchema.validate!(raw)
      new(raw)
    rescue PolicyError
      raise
    rescue StandardError => e
      raise PolicyError, "Failed to load policy file: #{e.message}"
    end

    def initialize(raw, warn_io: $stderr)
      raw ||= {}
      @keys = raw.fetch('keys', {})
      warn_on_legacy_resource_ids(warn_io)
    end

    def authorize(key_id, method, path, query = {})
      key_config = @keys[key_id]
      return nil unless key_config

      query ||= {}
      rule = find_matching_rule(key_config.fetch('allowed', []), method, path, query)
      return nil unless rule

      transforms = deep_merge(key_config.fetch('transforms', {}), rule.fetch('transforms', {}))
      query_allowed = extract_query_allowed(rule)
      headers_allowed = extract_allowed_request_headers(key_config, rule)
      { key_id: key_id, rule: rule, transforms: transforms,
        query_allowed: query_allowed, allowed_request_headers: headers_allowed }
    end

    private

    def find_matching_rule(rules, method, path, query)
      normalized_method = method.to_s.upcase

      rules.find do |rule|
        rule_matches?(rule, normalized_method, path, query)
      end
    end

    def rule_matches?(rule, normalized_method, path, query)
      return false unless rule['method'].to_s.upcase == normalized_method

      matcher = compile_path(rule['path'])
      match = matcher[:regex].match(path.to_s)
      return false unless match

      payload = matcher[:keys].zip(match.captures).to_h
      return false unless resource_allowed?(rule['resource_ids'], payload)

      query_allowed?(rule['query'], query)
    end

    def query_allowed?(query_config, query)
      return true if query_config.nil?
      raise PolicyError, 'query rule block must be a hash' unless query_config.is_a?(Hash)

      allowed = Array(query_config['allowed']).map(&:to_s)
      required = Array(query_config['required']).map(&:to_s)
      per_key_values = query_config['values'] || {}

      query_keys = query.keys.map(&:to_s)

      return false if allowed.any? && query_keys.any? { |key| !allowed.include?(key) }
      return false unless required.all? { |key| query_keys.include?(key) }

      per_key_values.all? do |key, allowed_values|
        next true unless query_keys.include?(key.to_s)

        allowed_values = Array(allowed_values).map(&:to_s)
        Array(query[key.to_s] || query[key]).all? { |value| allowed_values.include?(value.to_s) }
      end
    end

    def extract_query_allowed(rule)
      query_config = rule['query']
      return nil unless query_config.is_a?(Hash)

      allowed = Array(query_config['allowed']).map(&:to_s)
      allowed.empty? ? nil : allowed
    end

    def extract_allowed_request_headers(key_config, rule)
      (Array(key_config['allowed_request_headers']) + Array(rule['allowed_request_headers'])).map(&:to_s).uniq
    end

    def compile_path(template)
      unless template.is_a?(String) && !template.empty? && template.start_with?('/')
        raise PolicyError, "Invalid policy path: #{template.inspect}"
      end

      { regex: Regexp.new("^#{build_path_regex(template)}$"), keys: extract_path_keys(template) }
    end

    def build_path_regex(template)
      template.split('/').map do |segment|
        if segment.start_with?(':')
          '([^/]+)'
        else
          Regexp.escape(segment)
        end
      end.join('/')
    end

    def extract_path_keys(template)
      template.split('/').each_with_object([]) do |segment, keys|
        next unless segment.start_with?(':')

        key = segment[1..]
        raise PolicyError, "Invalid path parameter name: #{key.inspect}" unless key.match?(/^[A-Za-z0-9_]+$/)

        keys << key
      end
    end

    def resource_allowed?(resource_ids, payload)
      return true if resource_ids.nil? || (resource_ids.respond_to?(:empty?) && resource_ids.empty?)

      case resource_ids
      when Hash
        resource_ids.all? do |param_name, allowed|
          allowed_values = Array(allowed)
          next true if allowed_values.empty?

          unless payload.key?(param_name.to_s)
            raise PolicyError,
                  "resource_ids references unknown path param: #{param_name.inspect}"
          end

          allowed_values.include?(payload[param_name.to_s])
        end
      when Array
        first_param_value = payload.values.first
        resource_ids.include?(first_param_value)
      else
        raise PolicyError, "resource_ids must be a hash or array, got: #{resource_ids.class}"
      end
    end

    def deep_merge(left, right, path = [])
      return merge_whitelist(left, right) if path.last == 'whitelist'

      return right unless left.is_a?(Hash) && right.is_a?(Hash)

      left.merge(right) do |key, old_val, new_val|
        deep_merge(old_val, new_val, path + [key])
      end
    end

    def merge_whitelist(left, right)
      return right if left.nil?
      return left if right.nil?
      return left & right if left.is_a?(Array) && right.is_a?(Array)

      left_hash = whitelist_to_hash(left)
      right_hash = whitelist_to_hash(right)
      return right_hash unless left_hash.is_a?(Hash) && right_hash.is_a?(Hash)

      (left_hash.keys | right_hash.keys).to_h { |key| [key, merge_whitelist_field(left_hash, right_hash, key)] }
    end

    def merge_whitelist_field(left_hash, right_hash, key)
      return Array(left_hash[key]) & Array(right_hash[key]) if left_hash.key?(key) && right_hash.key?(key)

      left_hash[key] || right_hash[key]
    end

    def whitelist_to_hash(value)
      case value
      when Array then { 'value' => value }
      when Hash then value
      end
    end

    def warn_on_legacy_resource_ids(warn_io)
      @keys.each do |key_id, key_config|
        Array(key_config && key_config['allowed']).each_with_index do |rule, index|
          next unless rule.is_a?(Hash) && rule['resource_ids'].is_a?(Array) && !rule['resource_ids'].empty?

          warn_io.puts("[proxynoid] DEPRECATION: keys.#{key_id}.allowed[#{index}].resource_ids " \
                       'uses legacy array form; prefer hash form like {app_id: [...]}')
        end
      end
    end
  end

  class PolicyError < StandardError; end
end
