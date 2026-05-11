# typed: true
# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module Proxy
  # Fan-out for audit events. Always writes to stdout. When a webhook URL is
  # configured it ALSO POSTs each event from a background worker — fire and
  # forget, bounded queue, drop on full. The audit path never blocks the
  # request path on a slow remote sink.
  class AuditSink
    DEFAULT_QUEUE_SIZE = 1000
    DROP_WARN_INTERVAL = 60

    def initialize(stdout: $stdout, webhook_url: nil, queue_size: DEFAULT_QUEUE_SIZE,
                   start_worker: true, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                   warn_io: $stderr, http_timeout: 5)
      @stdout = stdout
      @stdout.sync = true if @stdout.respond_to?(:sync=)
      @webhook_url = webhook_url
      @queue = SizedQueue.new(queue_size)
      @dropped = 0
      @last_warn_at = nil
      @clock = clock
      @warn_io = warn_io
      @http_timeout = http_timeout
      @worker = nil
      launch_worker if start_worker && @webhook_url
    end

    def write(payload)
      json = JSON.generate(payload)
      @stdout.puts(json)
      enqueue(json) if @webhook_url
    end

    def drain
      return if @worker.nil?

      @queue.close if @queue.respond_to?(:close)
      @worker.join
    end

    private

    def enqueue(json)
      @queue.push(json, true)
    rescue ThreadError
      @dropped += 1
      warn_if_due
    end

    def warn_if_due
      now = @clock.call
      return if @last_warn_at && (now - @last_warn_at) < DROP_WARN_INTERVAL

      @last_warn_at = now
      @warn_io.puts("[proxynoid] audit webhook dropped #{@dropped} events; queue full")
    end

    def launch_worker
      @worker = Thread.new { worker_loop }
      @worker.report_on_exception = true
    end

    def worker_loop
      uri = URI(@webhook_url)
      loop do
        json = @queue.pop
        break if json.nil?

        post(uri, json)
      end
    rescue StandardError => e
      @warn_io.puts("[proxynoid] audit worker crashed: #{e.class}: #{e.message}")
    end

    def post(uri, json)
      Net::HTTP.start(uri.hostname, uri.port,
                      use_ssl: uri.scheme == 'https',
                      open_timeout: @http_timeout, read_timeout: @http_timeout) do |http|
        req = Net::HTTP::Post.new(uri.request_uri, 'Content-Type' => 'application/json')
        req.body = json
        http.request(req)
      end
    rescue StandardError => e
      warn_post_failure(e)
    end

    def warn_post_failure(error)
      now = @clock.call
      return if @last_warn_at && (now - @last_warn_at) < DROP_WARN_INTERVAL

      @last_warn_at = now
      @warn_io.puts("[proxynoid] audit webhook POST failed: #{error.class}: #{error.message}")
    end
  end
end
