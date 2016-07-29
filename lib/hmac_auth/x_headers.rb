module HMACAuth
  module XHeaders
    REQUEST_ID = 'X-Request-ID'.freeze
    SIGNATURE  = 'X-Signature'.freeze

    class << self
      def rack_variable(str)
        "HTTP_#{str}".upcase.gsub('-', '_')
      end

      def rack_request_id
        rack_variable(REQUEST_ID)
      end

      def rack_signature
        rack_variable(SIGNATURE)
      end
    end
  end
end
