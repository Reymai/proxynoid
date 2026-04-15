# typed: false
# frozen_string_literal: true

require 'net/http'
require 'json'
require 'uri'
require 'ipaddr'

module Proxy
  class GithubIps
    DEFAULT_META_URL = 'https://api.github.com/meta'
    REFRESH_SECONDS = 4 * 60 * 60

    def initialize(static_ranges = [])
      @static_ranges = static_ranges.freeze
      @cidrs = []
      @mutex = Mutex.new
      ready = refresh!
      unless ready || @static_ranges.any?
        raise 'Unable to initialize GitHub Actions IP ranges and no static ranges provided'
      end

      start_background_refresh
    end

    def include?(ip)
      return false if ip.nil? || ip.strip.empty?

      @mutex.synchronize do
        @cidrs.any? { |cidr| cidr.include?(IPAddr.new(ip)) }
      end
    rescue StandardError
      false
    end

    private

    # rubocop:disable Naming/PredicateMethod
    def refresh!
      fetched = fetch_github_ranges
      @mutex.synchronize do
        @cidrs = (@static_ranges + fetched).map { |cidr| IPAddr.new(cidr) }
      end
      fetched.any?
    end
    # rubocop:enable Naming/PredicateMethod

    def fetch_github_ranges
      uri = URI(DEFAULT_META_URL)
      request = Net::HTTP::Get.new(uri)
      request['User-Agent'] = 'proxynoid-github-actions-ip-sync'

      Net::HTTP.start(uri.hostname, uri.port, use_ssl: true, open_timeout: 10, read_timeout: 10) do |http|
        response = http.request(request)
        return [] unless response.is_a?(Net::HTTPSuccess)

        body = JSON.parse(response.body)
        Array(body['actions']).map(&:to_s).reject(&:empty?)
      end
    rescue StandardError
      []
    end

    def start_background_refresh
      Thread.new do
        loop do
          sleep REFRESH_SECONDS
          refresh!
        end
      end.tap(&:abort_on_exception)
    end
  end
end
