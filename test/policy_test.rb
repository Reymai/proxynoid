# frozen_string_literal: true

require 'tempfile'
require 'stringio'
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
    assert_equal([], result[:transforms]['response']['mask_values']['whitelist'])
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

  def test_load_handles_empty_policy_file
    file = Tempfile.new('policy.yml')
    file.close

    policy = Proxy::Policy.load(file.path)
    assert_nil policy.authorize('deploy_pipeline', 'GET', '/v2/apps/abc')
  ensure
    file&.unlink
  end

  def test_intersects_key_and_endpoint_whitelists
    raw = {
      'keys' => {
        'test_pipeline' => {
          'transforms' => {
            'response' => {
              'mask_values' => {
                'whitelist' => %w[production staging]
              }
            }
          },
          'allowed' => [
            {
              'method' => 'GET',
              'path' => '/v2/apps/:app_id/envs',
              'transforms' => {
                'response' => {
                  'mask_values' => {
                    'whitelist' => ['production']
                  }
                }
              }
            }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw)
    result = policy.authorize('test_pipeline', 'GET', '/v2/apps/abc/envs')

    assert_equal(['production'], result[:transforms]['response']['mask_values']['whitelist'])
  end

  def test_allows_any_id_when_resource_ids_nil
    raw = {
      'keys' => {
        'test_pipeline' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/apps/:app_id/envs', 'resource_ids' => nil }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw)
    assert policy.authorize('test_pipeline', 'GET', '/v2/apps/any-id/envs')
  end

  def test_head_request_matches_get_rule_by_default
    raw = {
      'keys' => {
        'p' => { 'allowed' => [{ 'method' => 'GET', 'path' => '/v2/x' }] }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    assert policy.authorize('p', 'HEAD', '/v2/x', {})
  end

  def test_head_request_does_not_match_when_allow_head_false
    raw = {
      'keys' => {
        'p' => { 'allowed' => [{ 'method' => 'GET', 'path' => '/v2/x', 'allow_head' => false }] }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    assert_nil policy.authorize('p', 'HEAD', '/v2/x', {})
  end

  def test_trailing_slash_is_stripped_unless_rule_template_keeps_it
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/apps' },
            { 'method' => 'GET', 'path' => '/v2/with-slash/' }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    assert policy.authorize('p', 'GET', '/v2/apps/', {})
    assert policy.authorize('p', 'GET', '/v2/apps', {})
    assert policy.authorize('p', 'GET', '/v2/with-slash/', {})
  end

  def test_query_allowed_rejects_unknown_keys
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/apps', 'query' => { 'allowed' => %w[page per_page] } }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    assert policy.authorize('p', 'GET', '/v2/apps', { 'page' => '2' })
    assert_nil policy.authorize('p', 'GET', '/v2/apps', { 'evil' => '1' })
  end

  def test_query_required_keys_must_be_present
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/x', 'query' => { 'allowed' => ['page'], 'required' => ['page'] } }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    assert policy.authorize('p', 'GET', '/v2/x', { 'page' => '1' })
    assert_nil policy.authorize('p', 'GET', '/v2/x', {})
  end

  def test_query_per_key_value_constraints
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            {
              'method' => 'GET',
              'path' => '/v2/x',
              'query' => { 'allowed' => ['per_page'], 'values' => { 'per_page' => %w[10 25] } }
            }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    assert policy.authorize('p', 'GET', '/v2/x', { 'per_page' => '10' })
    assert_nil policy.authorize('p', 'GET', '/v2/x', { 'per_page' => '999' })
  end

  def test_query_allowed_returns_keys_in_authorize_result
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/x', 'query' => { 'allowed' => %w[page per_page] } }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    result = policy.authorize('p', 'GET', '/v2/x', { 'page' => '2' })
    assert_equal(%w[page per_page], result[:query_allowed])
  end

  def test_hash_form_resource_ids_enforces_each_param
    raw = {
      'keys' => {
        'test_pipeline' => {
          'allowed' => [
            {
              'method' => 'POST',
              'path' => '/v2/apps/:app_id/components/:component',
              'resource_ids' => {
                'app_id' => ['abc-123'],
                'component' => %w[worker web]
              }
            }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)

    assert policy.authorize('test_pipeline', 'POST', '/v2/apps/abc-123/components/worker')
    assert_nil policy.authorize('test_pipeline', 'POST', '/v2/apps/abc-123/components/database')
    assert_nil policy.authorize('test_pipeline', 'POST', '/v2/apps/other-app/components/worker')
  end

  def test_hash_form_resource_ids_skips_param_with_empty_array
    raw = {
      'keys' => {
        'test_pipeline' => {
          'allowed' => [
            {
              'method' => 'GET',
              'path' => '/v2/apps/:app_id/components/:component',
              'resource_ids' => {
                'app_id' => ['abc-123'],
                'component' => []
              }
            }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    assert policy.authorize('test_pipeline', 'GET', '/v2/apps/abc-123/components/anything')
  end

  def test_hash_form_resource_ids_rejects_unknown_path_param
    raw = {
      'keys' => {
        'test_pipeline' => {
          'allowed' => [
            {
              'method' => 'GET',
              'path' => '/v2/apps/:app_id',
              'resource_ids' => { 'component' => ['worker'] }
            }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    assert_raises(Proxy::PolicyError) do
      policy.authorize('test_pipeline', 'GET', '/v2/apps/abc')
    end
  end

  def test_legacy_array_resource_ids_emits_deprecation_warning
    raw = {
      'keys' => {
        'legacy_pipeline' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/apps/:app_id', 'resource_ids' => ['abc'] }
          ]
        }
      }
    }

    warn_io = StringIO.new
    Proxy::Policy.new(raw, warn_io: warn_io)
    assert_match(/DEPRECATION.*legacy_pipeline.*resource_ids/, warn_io.string)
  end

  def test_legacy_array_resource_ids_matches_only_first_path_param
    raw = {
      'keys' => {
        'legacy_pipeline' => {
          'allowed' => [
            {
              'method' => 'GET',
              'path' => '/v2/apps/:app_id/components/:component',
              'resource_ids' => ['abc-123']
            }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw, warn_io: StringIO.new)
    assert policy.authorize('legacy_pipeline', 'GET', '/v2/apps/abc-123/components/worker')
    assert_nil policy.authorize('legacy_pipeline', 'GET', '/v2/apps/other/components/abc-123')
  end

  def test_intersects_hash_form_whitelists_per_field
    raw = {
      'keys' => {
        'test_pipeline' => {
          'transforms' => {
            'response' => {
              'mask_values' => {
                'whitelist' => {
                  'value' => %w[production staging],
                  'token' => ['legacy-token']
                }
              }
            }
          },
          'allowed' => [
            {
              'method' => 'GET',
              'path' => '/v2/apps/:app_id/envs',
              'transforms' => {
                'response' => {
                  'mask_values' => {
                    'whitelist' => {
                      'value' => ['production']
                    }
                  }
                }
              }
            }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw)
    result = policy.authorize('test_pipeline', 'GET', '/v2/apps/abc/envs')
    merged = result[:transforms]['response']['mask_values']['whitelist']

    assert_equal(['production'], merged['value'])
    assert_equal(['legacy-token'], merged['token'])
  end

  def test_mixed_array_and_hash_whitelist_normalizes_to_hash
    raw = {
      'keys' => {
        'test_pipeline' => {
          'transforms' => {
            'response' => { 'mask_values' => { 'whitelist' => %w[production staging] } }
          },
          'allowed' => [
            {
              'method' => 'GET',
              'path' => '/v2/apps/:app_id/envs',
              'transforms' => {
                'response' => {
                  'mask_values' => { 'whitelist' => { 'value' => ['production'], 'token' => [] } }
                }
              }
            }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw)
    result = policy.authorize('test_pipeline', 'GET', '/v2/apps/abc/envs')
    merged = result[:transforms]['response']['mask_values']['whitelist']

    assert_equal(['production'], merged['value'])
    assert_equal([], merged['token'])
  end

  def test_allows_any_id_when_resource_ids_empty
    raw = {
      'keys' => {
        'test_pipeline' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/apps/:app_id/envs', 'resource_ids' => [] }
          ]
        }
      }
    }

    policy = Proxy::Policy.new(raw)
    assert policy.authorize('test_pipeline', 'GET', '/v2/apps/any-id/envs')
  end
end
