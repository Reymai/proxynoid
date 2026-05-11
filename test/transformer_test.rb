# frozen_string_literal: true

require_relative 'test_helper'
require 'json'

class TransformerTest < Minitest::Test
  def setup
    @transformer = Proxy::Transformer.new(1)
  end

  def test_masks_value_field_when_not_whitelisted
    body = { 'value' => 'secret' }.to_json
    headers = { 'content-type' => 'application/json' }
    transforms = { 'response' => { 'mask_values' => { 'whitelist' => [] } } }

    assert_equal({ 'value' => '[FILTERED]' }.to_json, @transformer.apply(body, headers, transforms))
  end

  def test_preserves_value_when_whitelisted
    body = { 'value' => 'production' }.to_json
    headers = { 'content-type' => 'application/json' }
    transforms = { 'response' => { 'mask_values' => { 'whitelist' => ['production'] } } }

    assert_equal(body, @transformer.apply(body, headers, transforms))
  end

  def test_masks_nested_value_fields
    body = { 'items' => [{ 'value' => 'x' }, { 'value' => 'production' }] }.to_json
    headers = { 'content-type' => 'application/json' }
    transforms = { 'response' => { 'mask_values' => { 'whitelist' => ['production'] } } }

    expected = { 'items' => [{ 'value' => '[FILTERED]' }, { 'value' => 'production' }] }.to_json
    assert_equal(expected, @transformer.apply(body, headers, transforms))
  end

  def test_rejects_payloads_over_max_size
    body = 'x' * ((1 * 1024 * 1024) + 1)
    headers = { 'content-type' => 'application/json' }
    transforms = { 'response' => { 'mask_values' => { 'whitelist' => [] } } }

    assert_raises(Proxy::ResponseSizeError) do
      @transformer.apply(body, headers, transforms)
    end
  end

  def test_returns_body_as_is_when_not_json
    body = 'not json'
    headers = { 'content-type' => 'application/json' }
    transforms = { 'response' => { 'mask_values' => { 'whitelist' => [] } } }

    assert_equal(body, @transformer.apply(body, headers, transforms))
  end

  def test_masks_custom_sensitive_keys
    body = { 'token' => 'sk_live_abc', 'name' => 'demo' }.to_json
    headers = { 'content-type' => 'application/json' }
    transforms = {
      'response' => {
        'mask_values' => {
          'keys' => %w[value token],
          'whitelist' => {}
        }
      }
    }

    expected = { 'token' => '[FILTERED]', 'name' => 'demo' }.to_json
    assert_equal(expected, @transformer.apply(body, headers, transforms))
  end

  def test_masks_keys_matching_pattern
    body = { 'app_secret' => 's', 'unrelated' => 'ok' }.to_json
    headers = { 'content-type' => 'application/json' }
    transforms = {
      'response' => {
        'mask_values' => {
          'keys' => [],
          'key_patterns' => ['(?i).*secret.*'],
          'whitelist' => {}
        }
      }
    }

    result = JSON.parse(@transformer.apply(body, headers, transforms))
    assert_equal('[FILTERED]', result['app_secret'])
    assert_equal('ok', result['unrelated'])
  end

  def test_applies_per_field_whitelist_in_hash_form
    body = { 'value' => 'production', 'token' => 'secret-token' }.to_json
    headers = { 'content-type' => 'application/json' }
    transforms = {
      'response' => {
        'mask_values' => {
          'keys' => %w[value token],
          'whitelist' => {
            'value' => ['production'],
            'token' => []
          }
        }
      }
    }

    result = JSON.parse(@transformer.apply(body, headers, transforms))
    assert_equal('production', result['value'])
    assert_equal('[FILTERED]', result['token'])
  end

  def test_legacy_array_whitelist_still_applies_to_value
    body = { 'value' => 'production' }.to_json
    headers = { 'content-type' => 'application/json' }
    transforms = { 'response' => { 'mask_values' => { 'whitelist' => ['production'] } } }

    assert_equal(body, @transformer.apply(body, headers, transforms))
  end

  def test_invalid_regex_pattern_is_skipped_silently
    body = { 'value' => 'x' }.to_json
    headers = { 'content-type' => 'application/json' }
    transforms = {
      'response' => {
        'mask_values' => {
          'key_patterns' => ['['],
          'whitelist' => []
        }
      }
    }

    expected = { 'value' => '[FILTERED]' }.to_json
    assert_equal(expected, @transformer.apply(body, headers, transforms))
  end
end
