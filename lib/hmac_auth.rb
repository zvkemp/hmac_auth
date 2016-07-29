require "hmac_auth/version"
require "hmac_auth/x_headers"
require "hmac_auth/faraday"

module HMACAuth
  Config = Struct.new(:default_key, :default_secret, :digest_algorithm)

  def self.config
    @config ||= Config.new.tap do |config|
      config.digest_algorithm = 'sha1'
    end
  end

  class << self
    def sign(secret:, request_id:, path:, digest_algorithm: default_digest_algorithm)
      OpenSSL::HMAC.new(
        [secret, request_id, path].join('-'), OpenSSL::Digest.new(digest_algorithm)
      ).hexdigest
    end

    def verify(signature:, **signing_options)
      sign(**signing_options) == signature
    end

    # Extracts and yields the signing key to a block so
    # it can be used to look up the signing secret.
    #
    # Signing secret can also be passed in as a keyword.
    def verify_rack_env(env, secret: nil)
      request_id = env.fetch(HMACAuth::XHeaders.rack_request_id)
      key = request_id.split('-').first

      secret = (secret or yield key)

      verify(
        signature: env.fetch(HMACAuth::XHeaders.rack_signature),
        request_id: request_id,
        path: env.fetch('REQUEST_PATH'),
        secret: secret
      )
    end

    private

    def default_digest_algorithm
      config.digest_algorithm
    end
  end
end
