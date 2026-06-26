# frozen_string_literal: true

require "webrick"
require "webrick/https"
require "stringio"

module Identizer
  # Runs the Rack App standalone over HTTPS (WEBrick). This is only needed for
  # the standalone/CLI use case — when mounting Identizer inside an existing
  # Rack/Rails app you use App directly and never touch this.
  class Server
    def self.start(config = Identizer.configuration, app: nil)
      new(config, app: app).start
    end

    def initialize(config = Identizer.configuration, app: nil)
      @config = config
      @app = app || App.new(config)
    end

    def start
      $stdout.sync = true
      cert, key, cert_path = TLS.resolve(@config)
      server = build_server(cert, key)
      server.mount_proc("/") { |request, response| dispatch(request, response) }

      trap("INT") { server.shutdown }
      trap("TERM") { server.shutdown }

      print_banner(cert_path)
      server.start
    end

    private

    def build_server(cert, key)
      WEBrick::HTTPServer.new(
        Port: @config.port,
        BindAddress: @config.host,
        SSLEnable: true,
        SSLCertificate: cert,
        SSLPrivateKey: key,
        Logger: WEBrick::Log.new($stderr, WEBrick::Log::WARN),
        AccessLog: []
      )
    end

    def dispatch(request, response)
      status, headers, body = @app.call(rack_env(request))
      response.status = status
      headers.each { |key, value| response[key] = value }
      response.body = +""
      body.each { |chunk| response.body << chunk }
    ensure
      body.close if body.respond_to?(:close)
    end

    # Translate a WEBrick request into a minimal Rack env.
    def rack_env(request)
      body = request.body.to_s
      env = {
        "REQUEST_METHOD" => request.request_method,
        "SCRIPT_NAME" => "",
        "PATH_INFO" => request.path,
        "QUERY_STRING" => request.query_string.to_s,
        "SERVER_NAME" => (request.host || @config.url_host).to_s,
        "SERVER_PORT" => @config.port.to_s,
        "CONTENT_LENGTH" => body.bytesize.to_s,
        "rack.input" => StringIO.new(body),
        "rack.errors" => $stderr,
        "rack.url_scheme" => "https"
      }
      request.header.each do |key, values|
        env["HTTP_#{key.upcase.tr('-', '_')}"] = values.join(", ")
      end
      env["CONTENT_TYPE"] = request.content_type if request.content_type
      env
    end

    def print_banner(cert_path)
      base = @config.base_url
      puts <<~BANNER
        ────────────────────────────────────────────────────────────
        Identizer listening on #{base} (TLS)
        ────────────────────────────────────────────────────────────
        Dashboard (identities + provider cheatsheet):
          #{base}/

        TLS cert: #{cert_path}
        Trust it for the app's server-to-server calls (token/userinfo + AWS SDK):
          recommended — mkcert: `mkcert -install && mkcert localhost 127.0.0.1`,
            then pass --tls-cert / --tls-key (or set IDENTIZER_TLS_CERT/KEY);
          or (self-signed) export SSL_CERT_FILE=#{cert_path} for the app process.
        ────────────────────────────────────────────────────────────
      BANNER
    end
  end
end
