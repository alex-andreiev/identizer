# frozen_string_literal: true

require "optparse"

module Identizer
  # `identizer` command: configure from flags/env and boot the standalone server.
  class CLI
    def self.start(argv)
      new(argv).run
    end

    def initialize(argv)
      @argv = argv
    end

    def run
      Server.start(configure(Identizer.configuration))
    end

    # Parse the flags onto a configuration and apply any saved settings, without
    # starting the server. Separated out so it can be exercised in tests.
    def configure(config = Identizer.configuration)
      parser(config).parse!(@argv)
      config.apply_persisted_settings! # web-admin saved password/signing
      config
    end

    private

    def parser(config)
      OptionParser.new do |opts|
        opts.banner = "Usage: identizer [options]"

        opts.on("--port PORT", Integer, "Listen port (default 9999)") { |value| config.port = value }
        opts.on("--host HOST", "Bind address (default 127.0.0.1)") { |value| config.host = value }
        opts.on("--url-host HOST", "Hostname used in advertised URLs (default localhost)") do |value|
          config.url_host = value
        end
        opts.on("--config-dir DIR", "Where identities + certs are stored") { |value| config.config_dir = value }
        opts.on("--tls-cert PATH", "TLS certificate (PEM)") { |value| config.tls_cert_path = value }
        opts.on("--tls-key PATH", "TLS private key (PEM)") { |value| config.tls_key_path = value }
        opts.on("--password PASS", "Shared sign-in password (default 'password')") do |value|
          config.shared_password = value
        end
        opts.on("--rs256", "Sign id_tokens with RS256 + publish JWKS") { config.signing = :rs256 }
        opts.on("-v", "--version", "Print version") do
          puts Identizer::VERSION
          exit
        end
        opts.on("-h", "--help", "Show this help") do
          puts opts
          exit
        end
      end
    end
  end
end
