# frozen_string_literal: true

require_relative 'test_helper'

class PolicyTest < Minitest::Test
  def setup
    policy_path = File.expand_path('../config/policies.yml', __dir__)
    @policy = Proxy::Policy.load(policy_path)
  end

  def test_authorizes_known_path_with_matching_resource_id
    result = @policy.authorize('deploy_pipeline', 'POST', '/v2/apps/abc-123-staging-id/deployments')
    refute_nil(result)
    assert_equal('deploy_pipeline', result[:key_id])
  end

  def test_denies_unknown_resource_id
    result = @policy.authorize('deploy_pipeline', 'POST', '/v2/apps/unknown-id/deployments')
    assert_nil(result)
  end

  def test_authorizes_get_envs_with_rule_specific_transforms
    result = @policy.authorize('deploy_pipeline', 'GET', '/v2/apps/abc-123-staging-id/envs')
    refute_nil(result)
    assert_equal(%w[production staging us-east-1], result[:transforms]['response']['mask_values']['whitelist'])
  end

  def test_rejects_templates_without_leading_slash
    raw = {
      'keys' => {
        'test_pipeline' => {
          'allowed' => [{ 'method' => 'GET', 'path' => 'v2/apps/:app_id' }]
        }
      }
    }

    policy = Proxy::Policy.new(raw)
    assert_raises(Proxy::PolicyError) do
      policy.authorize('test_pipeline', 'GET', '/v2/apps/abc')
    end
  end

  def test_rejects_invalid_dynamic_segment_names
    raw = {
      'keys' => {
        'test_pipeline' => {
          'allowed' => [{ 'method' => 'GET', 'path' => '/v2/apps/:app-id' }]
        }
      }
    }

    policy = Proxy::Policy.new(raw)
    assert_raises(Proxy::PolicyError) do
      policy.authorize('test_pipeline', 'GET', '/v2/apps/abc')
    end
  end
end
