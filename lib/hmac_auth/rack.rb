require 'hmac_auth/x_headers'

module HMACAuth
  module Rack
    def self.verify(env, drift: HMACAuth.default_drift, ttl: HMACAuth.default_ttl, secret: nil)
      request_id = env.fetch(HMACAuth::XHeaders.rack_request_id)
      return false unless request_id
      key        = request_id.split('-').first
      secret     = (secret or yield key)
      HMACAuth.verify(
        signature: env.fetch(HMACAuth::XHeaders.rack_signature),
        method: env.fetch('REQUEST_METHOD'),
        ttl: ttl,
        drift: drift,
        request_id: request_id,
        path: env.fetch('PATH_INFO'),
        secret: secret,
        data: env.fetch('rack.input').read.tap { env['rack.input'].rewind }
      )
    rescue => e
      HMACAuth.config.error_handler.call(e)
      false
    end

    class Middleware
      VERIFIED_KEY = 'hmac_auth.verified'.freeze

      def initialize(app, secret)
        @app           = app
        @secret_lookup = secret.respond_to?(:call) ? secret : -> (*) { secret }
      end

      def call(env)
        env['hmac_auth.verified'] = HMACAuth::Rack.verify(env, &@secret_lookup)
        @app.call(env)
      end
    end
  end
end
