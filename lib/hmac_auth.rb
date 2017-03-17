require "hmac_auth/version"
require "hmac_auth/x_headers"
require "hmac_auth/faraday"

module HMACAuth
  Config = Struct.new(:default_key, :default_secret, :digest_algorithm, :ttl, :error_handler, :drift)

  def self.config
    @config ||= Config.new.tap do |config|
      config.digest_algorithm = 'sha1'
      config.ttl   = 5
      config.drift = 5
      config.error_handler = -> (err) { puts err }
    end
  end

  class << self
    def sign(secret:, method:, request_id:, path:, data:, timestamp: utc_timestamp, digest_algorithm: default_digest_algorithm)
      method = method.to_s.upcase
      path   = path.empty? ? '/' : path
      OpenSSL::HMAC.hexdigest(
        OpenSSL::Digest.new(digest_algorithm),
        secret,
        [method.to_s.upcase, request_id, path, data, timestamp].join('-'),
      )
    end

    def verify(signature:, ttl: default_ttl, drift: default_drift, **signing_options)
      # Welcome, time travellers!
      # In case the clock of the server signing the request is ahead by more than the
      # time it takes to receive the request, we could see failed verifications signatures
      # made around the time the second rolls over. Advance a bit into the future
      # (and compensate in the ttl) to prevent this.
      (utc_timestamp + drift).downto(0).take(ttl + drift).any? do |ts|
        sign(**(signing_options.merge(timestamp: ts))) == signature
      end
    end

    # Extracts and yields the signing key to a block so
    # it can be used to look up the signing secret.
    #
    # Signing secret can also be passed in as a keyword.
    # `ttl` is the maximum number of seconds a signed request remains valid.
    def verify_rack_env(env, drift: default_drift, ttl: default_ttl, secret: nil, &block)
      require 'hmac_auth/rack'
      HMACAuth::Rack.verify(env, drift: drift, ttl: ttl, secret: secret, &block)
    end

    def default_ttl
      config.ttl
    end

    def default_drift
      config.drift
    end

    private

    def default_digest_algorithm
      config.digest_algorithm
    end

    def utc_timestamp
      Time.now.utc.to_i
    end
  end
end
