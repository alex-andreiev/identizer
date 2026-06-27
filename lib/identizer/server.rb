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
      server = mounted_server
      trap("INT") { server.shutdown }
      trap("TERM") { server.shutdown }
      print_banner(@cert_path)
      server.start
    end

    # Build the WEBrick server with the Rack app mounted, without starting it.
    # Exposed so tests can boot/stop it on an ephemeral port.
    def mounted_server
      cert, key, @cert_path = TLS.resolve(@config)
      server = build_server(cert, key)
      server.mount_proc("/") { |request, response| dispatch(request, response) }
      server
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
      log_request(request, status)
      response.status = status
      headers.each { |key, value| response[key] = value }
      response.body = +""
      body.each { |chunk| response.body << chunk }
    ensure
      body.close if body.respond_to?(:close)
    end

    # A concise request line so you can watch the SSO flow as it happens.
    def log_request(request, status)
      return unless @config.request_logging

      puts "[identizer] #{Time.now.strftime('%H:%M:%S')} #{request.request_method} #{request.path} -> #{status}"
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
         🔑  Identizer is running — a local identity provider for SSO testing

         Dashboard   #{base}/
                     (manage users & settings, copy provider values)
         Sign in     any directory user · password: "#{@config.shared_password}"
        #{hosts_hint}

         Point your app's SSO config at:
           OIDC      issuer #{base}  (discovery at /.well-known/openid-configuration)
           SAML      metadata #{base}/metadata · SSO #{base}/saml/sso
           OAuth2    authorize / token / userinfo under #{base}
           Cognito   COGNITO_ENDPOINT=#{base}
        #{ldap_banner_line}
         New to SSO? Open the dashboard → Docs → "Getting started".

         TLS: self-signed cert at #{cert_path}
              trust it for server-to-server calls: export SSL_CERT_FILE=#{cert_path}
              (or use mkcert + --tls-cert/--tls-key). Press Ctrl-C to stop.
        ────────────────────────────────────────────────────────────
      BANNER
    end

    def hosts_hint
      return "" if @config.url_host == "localhost"

      " Custom domain → add to /etc/hosts:  127.0.0.1  #{@config.url_host}\n " \
        "(the self-signed cert already covers it)\n"
    end

    def ldap_banner_line
      host = @config.ldap_host || @config.host
      lines = []
      lines << "LDAP listener:  ldap://#{host}:#{@config.ldap_port}" if @config.ldap_port
      lines << "LDAPS listener: ldaps://#{host}:#{@config.ldaps_port}" if @config.ldaps_port
      lines.empty? ? "" : "#{lines.join("\n")}\n"
    end
  end
end
