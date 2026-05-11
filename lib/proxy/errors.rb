# typed: true
# frozen_string_literal: true

module Proxy
  # Base for any proxy error that should surface a stable error code in audit logs.
  # Codes follow the taxonomy `<group>.<reason>` so log consumers can match on prefixes.
  class ProxyError < StandardError
    attr_reader :code

    def initialize(message, code:)
      super(message)
      @code = code
    end
  end

  class ResponseSizeError < ProxyError
    def initialize(message = 'Payload exceeds configured MAX_PAYLOAD_MB', code: 'upstream.size_exceeded')
      super
    end
  end

  class UpstreamError < ProxyError
    def initialize(message, code: 'upstream.error')
      super
    end
  end
end
