require "hmac_auth/version"
require "hmac_auth/x_headers"
require "hmac_auth/faraday"

module HMACAuth
  Config = Struct.new(:default_key, :default_secret, :digest_algorithm, :ttl)

  def self.config
    @config ||= Config.new.tap do |config|
      config.digest_algorithm = 'sha1'
      config.ttl = 3
    end
  end

  class << self
    def sign(secret:, request_id:, path:, timestamp: utc_timestamp, digest_algorithm: default_digest_algorithm)
      OpenSSL::HMAC.new(
        [secret, request_id, path, timestamp].join('-'), OpenSSL::Digest.new(digest_algorithm)
      ).hexdigest
    end

    def verify(signature:, ttl: default_ttl, **signing_options)
      utc_timestamp.downto(0).take(ttl).any? do |ts|
        sign(**(signing_options.merge(timestamp: ts))) == signature
      end
    end

    # Extracts and yields the signing key to a block so
    # it can be used to look up the signing secret.
    #
    # Signing secret can also be passed in as a keyword.
    # `ttl` is the maximum number of seconds a signed request remains valid.
    def verify_rack_env(env, ttl: default_ttl, secret: nil)
      request_id = env.fetch(HMACAuth::XHeaders.rack_request_id)
      key        = request_id.split('-').first
      secret     = (secret or yield key)
      verify(
        signature: env.fetch(HMACAuth::XHeaders.rack_signature),
        ttl: ttl,
        request_id: request_id,
        path: env.fetch('PATH_INFO'),
        secret: secret
      )
    end

    private

    def default_ttl
      config.ttl
    end

    def default_digest_algorithm
      config.digest_algorithm
    end

    def utc_timestamp
      Time.now.utc.to_i
    end
  end
end
