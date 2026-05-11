# typed: true
# frozen_string_literal: true

require 'json'

module Proxy
  # /healthz and /readyz responders. Bypass auth, policy, and audit logging:
  # they exist for orchestrators (k8s, LBs, App Platform) to probe the process,
  # so each hit during a healthcheck loop would otherwise drown out the audit feed.
  class Health
    def initialize(github_ips)
      @github_ips = github_ips
    end

    def healthz
      json_response(200, status: 'ok')
    end

    def readyz
      if @github_ips.respond_to?(:ready?) && @github_ips.ready?
        json_response(200, status: 'ready')
      else
        json_response(503, status: 'not_ready', reason: 'no source-IP ranges loaded yet')
      end
    end

    private

    def json_response(code, body)
      [code, { 'Content-Type' => 'application/json' }, [JSON.generate(body)]]
    end
  end
end
