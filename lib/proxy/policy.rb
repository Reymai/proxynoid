# typed: true
# frozen_string_literal: true

require 'psych'

module Proxy
  class Policy
    def self.load(path)
      raw = Psych.safe_load(File.read(path), symbolize_names: false) || {}
      new(raw)
    rescue StandardError => e
      raise PolicyError, "Failed to load policy file: #{e.message}"
    end

    def initialize(raw)
      raw ||= {}
      @keys = raw.fetch('keys', {})
    end

    def authorize(key_id, method, path)
      key_config = @keys[key_id]
      return nil unless key_config

      rule = find_matching_rule(key_config.fetch('allowed', []), method, path)
      return nil unless rule

      transforms = deep_merge(key_config.fetch('transforms', {}), rule.fetch('transforms', {}))
      { key_id: key_id, rule: rule, transforms: transforms }
    end

    private

    def find_matching_rule(rules, method, path)
      normalized_method = method.to_s.upcase

      rules.find do |rule|
        rule_matches?(rule, normalized_method, path)
      end
    end

    def rule_matches?(rule, normalized_method, path)
      return false unless rule['method'].to_s.upcase == normalized_method

      matcher = compile_path(rule['path'])
      match = matcher[:regex].match(path.to_s)
      return false unless match

      payload = matcher[:keys].zip(match.captures).to_h
      resource_allowed?(rule['resource_ids'], payload)
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
      return true if resource_ids.nil? || resource_ids.empty?

      payload.values.any? { |value| resource_ids.include?(value) }
    end

    def deep_merge(left, right)
      return right unless left.is_a?(Hash) && right.is_a?(Hash)

      left.merge(right) do |_, old_val, new_val|
        deep_merge(old_val, new_val)
      end
    end
  end

  class PolicyError < StandardError; end
end
