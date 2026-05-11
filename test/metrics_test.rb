# frozen_string_literal: true

require_relative 'test_helper'
require_relative '../lib/proxy/metrics'

class MetricsTest < Minitest::Test
  def setup
    @metrics = Proxy::Metrics.new
  end

  def test_request_counter_emits_labeled_line
    @metrics.increment_request(key_id: 'deploy_pipeline', method: 'POST', outcome: 'allowed')
    text = @metrics.to_prometheus

    assert_match(/proxynoid_requests_total\{key_id="deploy_pipeline",method="POST",outcome="allowed"\} 1/, text)
  end

  def test_duration_histogram_buckets_and_sum
    @metrics.observe_upstream_duration_ms(40)
    @metrics.observe_upstream_duration_ms(200)
    text = @metrics.to_prometheus

    assert_match(/proxynoid_upstream_duration_ms_bucket\{le="50"\} 1/, text)
    assert_match(/proxynoid_upstream_duration_ms_bucket\{le="250"\} 2/, text)
    assert_match(/proxynoid_upstream_duration_ms_count 2/, text)
    assert_match(/proxynoid_upstream_duration_ms_sum 240.00/, text)
  end

  def test_github_refresh_and_policy_reload_counters
    @metrics.increment_github_refresh(result: 'success')
    @metrics.increment_policy_reload(result: 'failure')
    text = @metrics.to_prometheus

    assert_match(/proxynoid_github_ip_refresh_total\{result="success"\} 1/, text)
    assert_match(/proxynoid_policy_reloads_total\{result="failure"\} 1/, text)
  end

  def test_label_values_are_escaped
    @metrics.increment_request(key_id: 'a"b', method: 'GET', outcome: 'allowed')
    text = @metrics.to_prometheus

    assert_match(/key_id="a\\"b"/, text)
  end
end
