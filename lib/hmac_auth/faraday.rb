require 'faraday'
require 'hmac_auth/x_headers'
require 'securerandom'

module HMACAuth
  module Faraday
    def self.connection(options = {})
      ::Faraday.new do |conn|
        conn.request :hmac_auth, options
        conn.adapter *(Array(options[:adapter] || ::Faraday.default_adapter))
      end
    end

    class Middleware < ::Faraday::Middleware
      attr_reader :options

      def initialize(app, options = {})
        super(app)
        @options = options
      end

      def call(env)
        id = request_id
        env.request_headers[XHeaders::REQUEST_ID] = id
        env.request_headers[XHeaders::SIGNATURE] = hmac(env, request_id: id)

        @app.call(env)
      end

      private

      def key
        options.fetch(:key) { HMACAuth.config.default_key }
      end

      def request_id
        "#{key}-#{SecureRandom.hex}"
      end

      def hmac(env, request_id:)
        HMACAuth.sign(
          method: env.method.to_s.upcase,
          secret: secret,
          request_id: request_id,
          path: env.url.path,
          data: env.body.to_s,
          digest_algorithm: HMACAuth.config.digest_algorithm
        )
      end

      def secret
        options.fetch(:secret) { HMACAuth.config.default_secret }
      end

      def digest
        OpenSSL::Digest.new(HMACAuth.config.digest_algorithm)
      end
    end
  end
end

if defined?(::Faraday)
  Faraday::Request.register_middleware(hmac_auth: -> { HMACAuth::Faraday::Middleware })
end
