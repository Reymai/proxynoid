# typed: true
# frozen_string_literal: true

require 'rack'
require 'ipaddr'
require_relative 'errors'

module Proxy
  class Auth
    def initialize(config, github_ips, rate_limiter: nil)
      @config = config
      @github_ips = github_ips
      @rate_limiter = rate_limiter
    end

    def authenticate(env)
      request = Rack::Request.new(env)
      source_ip = extract_source_ip(env)
      enforce_rate_limit!(source_ip)

      token = request.get_header('HTTP_X_PROXY_TOKEN')&.strip

      unless source_ip_allowed?(source_ip)
        record_failure(source_ip)
        raise AuthenticationError.new('IP not allowed', code: 'auth.ip_denied')
      end

      if token.nil? || token.empty?
        record_failure(source_ip)
        raise AuthenticationError.new('Missing X-Proxy-Token', code: 'auth.token_missing')
      end

      key_id = find_key_id(token)
      unless key_id
        record_failure(source_ip)
        raise AuthenticationError.new('Invalid token', code: 'auth.token_invalid')
      end

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
      remote_addr = env['REMOTE_ADDR'].to_s
      return remote_addr unless trusted_proxy?(remote_addr)

      from_forwarded = parse_forwarded_for(env['HTTP_FORWARDED'])
      return from_forwarded if from_forwarded

      from_xff = parse_xff(env['HTTP_X_FORWARDED_FOR'])
      return from_xff if from_xff

      single = env['HTTP_X_REAL_IP'] || env['HTTP_X_CLIENT_IP']
      return single.to_s.strip unless single.nil? || single.strip.empty?

      remote_addr
    end

    def trusted_proxy?(ip)
      return false if ip.nil? || ip.empty?

      cidrs = trusted_proxy_cidrs
      return false if cidrs.empty?

      address = IPAddr.new(ip)
      cidrs.any? { |cidr| IPAddr.new(cidr).include?(address) }
    rescue StandardError
      false
    end

    def trusted_proxy_cidrs
      return @config.trusted_proxy_cidrs if @config.respond_to?(:trusted_proxy_cidrs)

      []
    end

    def parse_xff(header)
      return nil if header.nil? || header.strip.empty?

      candidates = header.split(',').map(&:strip).reject(&:empty?)
      # Rightmost-untrusted walk: pop trusted proxies from the right; the next entry is the client.
      candidates.reverse.each do |candidate|
        return candidate unless trusted_proxy?(candidate)
      end
      candidates.first
    end

    def parse_forwarded_for(header)
      return nil if header.nil? || header.strip.empty?

      # RFC 7239 — comma-separated forwarded-element, each with semicolon-separated pairs
      elements = header.split(',').map(&:strip)
      candidates = elements.map do |element|
        for_pair = element.split(';').map(&:strip).find { |pair| pair.downcase.start_with?('for=') }
        next nil unless for_pair

        value = for_pair.split('=', 2)[1].to_s.strip
        value = value.delete_prefix('"').delete_suffix('"')
        value = value.sub(/\A\[/, '').sub(/\]\z/, '')
        value.empty? ? nil : value
      end.compact

      return nil if candidates.empty?

      candidates.reverse.each do |candidate|
        return candidate unless trusted_proxy?(candidate)
      end
      candidates.first
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

    def enforce_rate_limit!(source_ip)
      return if @rate_limiter.nil?
      return if @rate_limiter.allow?(source_ip)

      raise RateLimitedError.new('Too many failed auth attempts',
                                 retry_after: @rate_limiter.retry_after_seconds)
    end

    def record_failure(source_ip)
      @rate_limiter&.record_failure(source_ip)
    end
  end

  class AuthenticationError < ProxyError
    def initialize(message, code: 'auth.error')
      super
    end
  end

  class RateLimitedError < ProxyError
    attr_reader :retry_after

    def initialize(message, retry_after:, code: 'auth.rate_limited')
      super(message, code: code)
      @retry_after = retry_after
    end
  end
end
