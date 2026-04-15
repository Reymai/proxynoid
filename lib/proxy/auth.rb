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
      request = Rack::Request.new(env)
      token = request.get_header('HTTP_X_PROXY_TOKEN')&.strip
      key_id = find_key_id(token)
      source_ip = extract_source_ip(env)

      raise AuthenticationError, 'IP not allowed' unless source_ip_allowed?(source_ip)
      raise AuthenticationError, 'Missing X-Proxy-Token' if token.nil? || token.empty?
      raise AuthenticationError, 'Invalid token' unless key_id

      key_id
    end

    private

    def find_key_id(token)
      return nil if token.nil? || token.empty?

      @config.proxy_keys.each do |id, secret|
        next unless secure_compare(secret, token)

        return id
      end

      nil
    end

    def extract_source_ip(env)
      request = Rack::Request.new(env)

      if internal_proxy_address?(env['REMOTE_ADDR'])
        internal_ip = extract_internal_client_ip(env)
        return internal_ip unless internal_ip.nil? || internal_ip.empty?
      end

      request.ip || env['REMOTE_ADDR'] || ''
    end

    def extract_internal_client_ip(env)
      env['HTTP_X_REAL_IP'] || env['HTTP_X_CLIENT_IP']
    end

    def internal_proxy_address?(ip)
      return false if ip.nil? || ip.empty?

      address = IPAddr.new(ip)
      address.private? || address.loopback?
    rescue StandardError
      false
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
