# frozen_string_literal: true

require_relative '../lib/proxy/server'

bind "tcp://0.0.0.0:#{ENV.fetch('PORT', '9292')}"
workers 0
threads 0, 16
environment ENV.fetch('RACK_ENV', 'production')

app Proxy::Server.new
