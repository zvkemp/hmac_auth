require 'spec_helper'
require 'hmac_auth/faraday'

describe HMACAuth do
  it 'has a version number' do
    expect(HMACAuth::VERSION).not_to be nil
  end

  describe 'signing' do
    let(:secret) { 'foo' }
    let(:request_id) { SecureRandom.hex }
    let(:path) { '/foo/bar' }
    let(:verification) do
      lambda do |opts = {}|
        options = { signature: signature, secret: secret, request_id: request_id, path: path }.merge(opts)
        HMACAuth.verify(**options)
      end
    end

    let(:signature) { HMACAuth.sign(secret: secret, request_id: request_id, path: path) }
    specify { expect(verification.call).to eq(true) }

    context 'expired request' do
      before do
        allow(HMACAuth).to receive(:utc_timestamp) { Time.now.utc.to_i - 10 }
        signature
        allow(HMACAuth).to receive(:utc_timestamp).and_call_original
      end
      specify { expect(verification.call).to eq(false) }
      specify('with ample ttl') { expect(verification.call(ttl: 15)).to eq(true) }
    end
  end

  describe HMACAuth::Faraday::Middleware do
    let(:app) { -> (env) { env } }
    let(:middleware) { described_class.new(app, key: 'key', secret: secrets['key'] ) }
    let(:path) { '/foo' }
    let(:env) do
      Faraday::Env.new.tap do |c|
        c.request_headers = {}
        c.url = URI(path)
      end
    end
    let(:request_headers) { middleware.call(env).request_headers }
    let(:secrets) { { 'key' => SecureRandom.hex } }
    let(:rack_env) do
      {
        'HTTP_X_REQUEST_ID' => request_headers['X-Request-ID'],
        'HTTP_X_SIGNATURE' => request_headers['X-Signature'],
        'PATH_INFO' => path
      }
    end

    specify 'header encoding' do
      expect(request_headers['X-Request-ID']).to start_with('key-')
      expect(request_headers.key?('X-Signature')).to eq(true)
    end


    context 'rack authorization' do
      specify 'incorrect secret' do
        expect(HMACAuth.verify_rack_env(rack_env, secret: 'secret')).to eq(false)
      end

      specify 'secret via block' do
        expect(HMACAuth.verify_rack_env(rack_env) { |key| secrets['key'] }).to eq(true)
      end
    end
  end
end
