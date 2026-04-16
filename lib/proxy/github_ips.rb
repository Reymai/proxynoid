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
    MAX_FETCH_ATTEMPTS = 3
    RETRY_PAUSE_SECONDS = 0.1

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

      attempt = 0
      while attempt < MAX_FETCH_ATTEMPTS
        attempt += 1

        begin
          Net::HTTP.start(uri.hostname, uri.port, use_ssl: true, open_timeout: 10, read_timeout: 10) do |http|
            response = http.request(request)
            return parse_actions_response(response) if response.is_a?(Net::HTTPSuccess)
          end
        rescue StandardError
          # Retry transient network and HTTP failures.
        ensure
          sleep(RETRY_PAUSE_SECONDS) if attempt < MAX_FETCH_ATTEMPTS
        end
      end

      []
    end

    def parse_actions_response(response)
      body = JSON.parse(response.body)
      Array(body['actions']).map(&:to_s).reject(&:empty?)
    rescue JSON::ParserError
      []
    end

    def start_background_refresh
      Thread.new do
        loop do
          sleep REFRESH_SECONDS
          success = refresh!
          warn("[proxynoid] GitHub IP refresh failed after #{MAX_FETCH_ATTEMPTS} attempts") unless success
        end
      end.tap(&:abort_on_exception)
    end
  end
end
