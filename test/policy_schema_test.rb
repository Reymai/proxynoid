# frozen_string_literal: true

require_relative 'test_helper'
require_relative '../lib/proxy/policy_schema'

class PolicySchemaTest < Minitest::Test
  def test_accepts_minimal_valid_policy
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/apps' }
          ]
        }
      }
    }

    Proxy::PolicySchema.validate!(raw)
  end

  def test_rejects_unknown_top_level_keys
    raw = { 'keys' => {}, 'extra' => 1 }
    error = assert_raises(Proxy::PolicyError) { Proxy::PolicySchema.validate!(raw) }
    assert_match(/unknown fields.*extra/, error.message)
  end

  def test_rejects_unknown_rule_field_typo
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/x', 'methd' => 'POST' }
          ]
        }
      }
    }

    error = assert_raises(Proxy::PolicyError) { Proxy::PolicySchema.validate!(raw) }
    assert_match(/keys\.p\.allowed\[0\].*methd/, error.message)
  end

  def test_rejects_invalid_http_method
    raw = {
      'keys' => {
        'p' => { 'allowed' => [{ 'method' => 'YEET', 'path' => '/v2/x' }] }
      }
    }

    error = assert_raises(Proxy::PolicyError) { Proxy::PolicySchema.validate!(raw) }
    assert_match(/keys\.p\.allowed\[0\]\.method/, error.message)
  end

  def test_rejects_path_without_leading_slash
    raw = {
      'keys' => {
        'p' => { 'allowed' => [{ 'method' => 'GET', 'path' => 'v2/x' }] }
      }
    }

    assert_raises(Proxy::PolicyError) { Proxy::PolicySchema.validate!(raw) }
  end

  def test_accepts_hash_form_resource_ids
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            {
              'method' => 'GET',
              'path' => '/v2/apps/:app_id',
              'resource_ids' => { 'app_id' => ['abc'] }
            }
          ]
        }
      }
    }

    Proxy::PolicySchema.validate!(raw)
  end

  def test_accepts_legacy_array_resource_ids
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/apps/:app_id', 'resource_ids' => ['abc'] }
          ]
        }
      }
    }

    Proxy::PolicySchema.validate!(raw)
  end

  def test_rejects_query_with_unknown_field
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/x', 'query' => { 'allwed' => ['page'] } }
          ]
        }
      }
    }

    error = assert_raises(Proxy::PolicyError) { Proxy::PolicySchema.validate!(raw) }
    assert_match(/allwed/, error.message)
  end

  def test_rejects_mask_whitelist_wrong_type
    raw = {
      'keys' => {
        'p' => {
          'transforms' => {
            'response' => { 'mask_values' => { 'whitelist' => 'not-a-list' } }
          },
          'allowed' => [{ 'method' => 'GET', 'path' => '/v2/x' }]
        }
      }
    }

    error = assert_raises(Proxy::PolicyError) { Proxy::PolicySchema.validate!(raw) }
    assert_match(/whitelist/, error.message)
  end

  def test_rejects_non_https_upstream
    raw = {
      'keys' => {
        'p' => {
          'allowed' => [
            { 'method' => 'GET', 'path' => '/v2/x', 'upstream' => 'http://insecure.example' }
          ]
        }
      }
    }

    assert_raises(Proxy::PolicyError) { Proxy::PolicySchema.validate!(raw) }
  end
end
