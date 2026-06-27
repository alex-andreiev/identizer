# frozen_string_literal: true

require "optparse"

module Identizer
  # `identizer` command: configure from flags/env and boot the standalone server.
  class CLI
    # Seeded on first run so the directory isn't empty and login works immediately.
    DEMO_USER = { mail: "demo@example.com", givenName: "Demo", sn: "User" }.freeze

    def self.start(argv)
      new(argv).run
    end

    def initialize(argv)
      @argv = argv
      @demo = true
    end

    def run
      config = configure(Identizer.configuration)
      start_ldap(config)
      Server.start(config)
    end

    # Parse the flags onto a configuration and apply any saved settings, without
    # starting the server. Separated out so it can be exercised in tests.
    def configure(config = Identizer.configuration)
      parser(config).parse!(@argv)
      config.apply_persisted_settings! # web-admin saved password/signing
      config.seed_identities = [DEMO_USER] if @demo && config.seed_identities.empty?
      load_sqlite(config) if config.sqlite_path
      config
    end

    private

    def load_sqlite(config)
      require "identizer/identity_store/sqlite_store"
      config.identity_store = IdentityStore::SqliteStore.new(
        path: config.sqlite_path, base_dn: config.ldap_base_dn, seed: config.seed_identities
      )
    rescue LoadError
      abort "--sqlite needs the sqlite3 gem. Add `gem \"sqlite3\"` to your Gemfile or `gem install sqlite3`."
    end

    def start_ldap(config)
      return unless config.ldap_port || config.ldaps_port

      require "identizer/ldap"
      Thread.new { Ldap::Server.new(config, port: config.ldap_port).start } if config.ldap_port
      Thread.new { Ldap::Server.new(config, port: config.ldaps_port, tls: true).start } if config.ldaps_port
    end

    def parser(config)
      OptionParser.new do |opts|
        opts.banner = "Usage: identizer [options]"

        opts.on("--port PORT", Integer, "Listen port (default 9999)") { |value| config.port = value }
        opts.on("--host HOST", "Bind address (default 127.0.0.1)") { |value| config.host = value }
        opts.on("--url-host HOST", "Hostname used in advertised URLs (default localhost)") do |value|
          config.url_host = value
        end
        opts.on("--domain HOST", "Serve under a custom domain (add it to /etc/hosts -> 127.0.0.1)") do |value|
          config.url_host = value
        end
        opts.on("--config-dir DIR", "Where identities + certs are stored") { |value| config.config_dir = value }
        opts.on("--tls-cert PATH", "TLS certificate (PEM)") { |value| config.tls_cert_path = value }
        opts.on("--tls-key PATH", "TLS private key (PEM)") { |value| config.tls_key_path = value }
        opts.on("--password PASS", "Shared sign-in password (default 'password')") do |value|
          config.shared_password = value
        end
        opts.on("--sqlite PATH", "Use a SQLite-backed directory at PATH (needs the sqlite3 gem)") do |value|
          config.sqlite_path = value
        end
        opts.on("--rs256", "Sign id_tokens with RS256 + publish JWKS") { config.signing = :rs256 }
        opts.on("--no-demo", "Don't seed the demo user on first run") { @demo = false }
        opts.on("--quiet", "Don't log requests") { config.request_logging = false }
        opts.on("--ldap-port PORT", Integer, "Also start an LDAP listener on PORT") { |value| config.ldap_port = value }
        opts.on("--ldaps-port PORT", Integer, "Also start an LDAPS (TLS) listener on PORT") do |value|
          config.ldaps_port = value
        end
        opts.on("--ldap-host HOST", "Bind address for the LDAP listener") { |value| config.ldap_host = value }
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
