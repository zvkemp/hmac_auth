module HMACAuth
  class SignedString
    # Wrapper around the request-signing code to allow
    # signatures for simple string values.

    attr_reader :string, :options

    def self.verify(string, compound_signature, opts = {})
      key, nonce, signature = compound_signature.split('-')
      secret = (opts[:secret] or yield key)
      raise 'secret not found' unless secret
      new(string, opts.merge(nonce: nonce, key: key, secret: secret)).verify(signature, opts)
    end

    def initialize(string, opts = {})
      raise ArgumentError unless string.is_a?(String)
      @string = string
      @options = opts
    end

    def signature(opts = {})
      @signature ||= "#{key}-#{nonce}-#{sign}"
    end

    def verify(signature, verification_opts = {})
      signature = signature.split('-').last
      HMACAuth.verify(
        signature: signature,
        **signing_opts.merge(verification_opts)
      )
    end

    private

    def sign(opts = {})
      HMACAuth.sign(**signing_opts)
    end

    def signing_opts
      { request_id: nonce, method: 'string', path: '', data: string, secret: secret }
    end

    def secret
      options[:secret] || HMACAuth.config.default_secret
    end

    def key
      options[:key] || HMACAuth.config.default_key
    end

    def nonce
      @nonce ||= options[:nonce] || SecureRandom.hex(3)
    end
  end
end
