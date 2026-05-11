# frozen_string_literal: true

require 'stringio'
require_relative 'test_helper'
require_relative '../lib/proxy/audit_sink'

class AuditSinkTest < Minitest::Test
  def setup
    WebMock.reset!
    WebMock.disable_net_connect!(allow_localhost: true)
  end

  def teardown
    WebMock.reset!
    WebMock.allow_net_connect!
  end

  def test_writes_to_stdout_in_json_form
    out = StringIO.new
    sink = Proxy::AuditSink.new(stdout: out, webhook_url: nil)
    sink.write(event: 'test', count: 3)

    assert_equal({ 'event' => 'test', 'count' => 3 }, JSON.parse(out.string.strip))
  end

  def test_posts_to_webhook_when_configured
    stub_request(:post, 'https://hooks.example/audit')
      .with(body: { event: 'test' }.to_json,
            headers: { 'Content-Type' => 'application/json' })
      .to_return(status: 200, body: '')

    out = StringIO.new
    sink = Proxy::AuditSink.new(stdout: out, webhook_url: 'https://hooks.example/audit')
    sink.write(event: 'test')
    sink.drain

    assert_requested(:post, 'https://hooks.example/audit', times: 1)
  end

  def test_drops_events_when_queue_is_full
    out = StringIO.new
    warn_io = StringIO.new
    sink = Proxy::AuditSink.new(stdout: out, webhook_url: 'https://hooks.example/audit',
                                queue_size: 1, start_worker: false, warn_io: warn_io,
                                clock: -> { 0.0 })

    3.times { sink.write(event: 'overflow') }

    assert_match(/audit webhook dropped/, warn_io.string)
    assert_equal 3, out.string.lines.size # stdout still gets every event
  end

  def test_logs_post_failures_at_most_once_per_minute
    stub_request(:post, 'https://hooks.example/audit').to_return(status: 500)

    out = StringIO.new
    warn_io = StringIO.new
    now = 0.0
    sink = Proxy::AuditSink.new(stdout: out, webhook_url: 'https://hooks.example/audit',
                                warn_io: warn_io, clock: -> { now })

    5.times { sink.write(event: 'fail') }
    sink.drain

    # Failures get warned at most once in the 60s window
    assert_operator warn_io.string.lines.size, :<=, 1
  end
end
