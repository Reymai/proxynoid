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
end
