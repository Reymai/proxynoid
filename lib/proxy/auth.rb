# typed: true
# frozen_string_literal: true

require 'rack'
require 'ipaddr'

module Proxy
  class Auth
    def initialize(config, github_ips)
      @config = config
      @github_ips = github_ips
    end

    def authenticate(env)
      key_id = find_key_id(env)
      source_ip = extract_source_ip(env)

      raise AuthenticationError, 'IP not allowed' unless source_ip_allowed?(source_ip)

      raise AuthenticationError, 'Missing X-Proxy-Token' unless key_id

      key_id
    end

    private

    def find_key_id(env)
      request = Rack::Request.new(env)
      token = request.get_header('HTTP_X_PROXY_TOKEN')&.strip
      return nil if token.nil? || token.empty?

      @config.proxy_keys.each do |id, secret|
        next unless secure_compare(secret, token)

        return id
      end

      nil
    end

    def extract_source_ip(env)
      request = Rack::Request.new(env)
      forwarded = env['HTTP_X_FORWARDED_FOR']
      candidate = forwarded && forwarded.split(',').first&.strip
      candidate || env['REMOTE_ADDR'] || request.ip || ''
    end

    def source_ip_allowed?(ip)
      return false if ip.nil? || ip.empty?
      return true if @github_ips.include?(ip)

      @config.allowed_ip_ranges.any? do |cidr|
        IPAddr.new(cidr).include?(IPAddr.new(ip))
      rescue StandardError
        false
      end
    end

    def secure_compare(left, right)
      return false unless left.is_a?(String) && right.is_a?(String)

      Rack::Utils.secure_compare(left.dup, right.dup)
    rescue StandardError
      false
    end
  end

  class AuthenticationError < StandardError; end
end
