require 'spec_helper'
require 'rack'
require 'thin'
require 'hmac_auth/faraday'
require 'hmac_auth/rack'
require 'json'

describe HMACAuth do
  it 'has a version number' do
    expect(HMACAuth::VERSION).not_to be nil
  end

  describe 'signing' do
    let(:secret) { 'foo' }
    let(:request_id) { SecureRandom.hex }
    let(:path) { '/foo/bar' }
    let(:method) { :get }
    let(:data) { '' }
    let(:digestables) do
      {
        method: method,
        data: data,
        secret: secret,
        request_id: request_id,
        path: path
      }
    end
    let(:verification) do
      lambda do |opts = {}|
        options = { signature: signature }.merge(digestables).merge(opts)
        HMACAuth.verify(**options)
      end
    end

    let(:signature) { HMACAuth.sign(**digestables) }
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
        c.method = :get
        c.request_headers = {}
        c.url = URI(path)
      end
    end
    let(:request_headers) { middleware.call(env).request_headers }
    let(:secrets) { { 'key' => SecureRandom.hex } }

    specify 'header encoding' do
      expect(request_headers['X-Request-ID']).to start_with('key-')
      expect(request_headers.key?('X-Signature')).to eq(true)
    end

    context 'rack authorization' do
      let(:rack_env) do
        {
          'HTTP_X_REQUEST_ID' => request_headers['X-Request-ID'],
          'HTTP_X_SIGNATURE' => request_headers['X-Signature'],
          'PATH_INFO' => path,
          'REQUEST_METHOD' => 'GET',
          'rack.input' => StringIO.new('')
        }
      end

      specify 'incorrect secret' do
        expect(HMACAuth.verify_rack_env(rack_env, secret: 'secret')).to eq(false)
      end

      specify 'secret via block' do
        expect(HMACAuth.verify_rack_env(rack_env) { |key| secrets[key] }).to eq(true)
      end
    end

    describe 'rack tests' do
      def app
        responder = lambda do |env|
          status = env['hmac_auth.verified'] ? 200 : 401
          [status, {}, env.inspect]
        end

        HMACAuth::Rack::Middleware.new(responder, 'secret')
      end
      def port; 9091 end
      def host; '127.0.0.1' end
      attr_accessor :server, :server_thread
      def run_server
        Proc.new do
          puts 'starting thin...'
          Rack::Handler::Thin.run(app, tag: 'hmac_test', :Host => host, :Port => port) do |server|
            self.server = server
          end
        end
      end

      before(:all) do
        self.server_thread = Thread.new(&run_server)
        Thread.pass until server && server.running?
      end

      after(:all) do
        server.stop!
        server_thread.join
      end

      let(:uri) { "http://#{host}:#{port}" }
      let(:body) { { foo: 'bar' }.to_json }

      specify 'signed get request' do
        expect(HMACAuth::Faraday.connection(key: 'key', secret: 'secret').get(uri).status).to eq(200)
      end

      specify 'unsigned get request' do
        expect(::Faraday.get(uri).status).to eq(401)
      end

      specify 'unsigned put request' do
        expect(::Faraday.post(uri) {|p| p.body = body }.status).to eq(401)
      end

      specify 'signed put request' do
        expect(HMACAuth::Faraday.connection(key: 'key', secret: 'secret').post(uri) {|p| p.body = body }.status).to eq(200)
      end
    end
  end
end
