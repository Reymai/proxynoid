# frozen_string_literal: true

require 'bundler/setup'
require 'minitest/autorun'
require 'webmock/minitest'

$LOAD_PATH.unshift(File.expand_path('../..', __dir__))
require_relative '../lib/proxy/server'
