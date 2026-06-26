# frozen_string_literal: true

module Identizer
  # Everything the provider needs to run, with sensible dev defaults. Replaces
  # the Rails.* / ENV reads of the original emulator with one explicit object.
  class Configuration
    attr_accessor :host, :port, :tls_cert_path, :tls_key_path, :config_dir,
                  :shared_password, :signing, :hs256_key, :scheme, :url_host, :ldap_base_dn
    attr_writer :identity_store, :base_url, :issuer, :seed_identities, :providers

    def initialize
      @host = "127.0.0.1"
      @port = Integer(ENV.fetch("IDENTIZER_PORT", ENV.fetch("SSO_MOCK_PORT", "9999")))
      @tls_cert_path = env_presence("IDENTIZER_TLS_CERT", "SSO_MOCK_TLS_CERT")
      @tls_key_path = env_presence("IDENTIZER_TLS_KEY", "SSO_MOCK_TLS_KEY")
      @config_dir = ENV.fetch("IDENTIZER_CONFIG_DIR", File.join(Dir.pwd, "tmp", "identizer"))
      @shared_password = "password"
      @signing = :hs256 # :hs256 (unsigned-style parity) or :rs256 (verifiable)
      @hs256_key = "identizer-development-key"
      @scheme = "https"
      @url_host = "localhost"
      @ldap_base_dn = "dc=identizer,dc=local"
      @seed_identities = []
    end

    # Public URL the provider advertises in metadata, discovery and redirects.
    def base_url
      @base_url ||= "#{scheme}://#{url_host}:#{port}"
    end

    def issuer
      @issuer ||= base_url
    end

    def rs256?
      signing == :rs256
    end

    def seed_identities
      Array(@seed_identities).map { |entry| DirectoryEntry.from(entry, base_dn: ldap_base_dn) }
    end

    def identity_store
      @identity_store ||= IdentityStore::ConfigStore.new(
        path: File.join(config_dir, "config.json"),
        seed: seed_identities,
        base_dn: ldap_base_dn
      )
    end

    # Cheatsheet rendered on the dashboard. Override to match your app's stack.
    def providers
      @providers || default_providers
    end

    def settings_path
      File.join(config_dir, "settings.json")
    end

    # Apply settings previously saved from the web admin (password, signing mode).
    # Called at boot; explicit flags/config still override afterwards.
    def apply_persisted_settings!
      data = JSON.parse(File.read(settings_path))
      self.shared_password = data["shared_password"] if data["shared_password"]
      self.signing = data["signing"].to_sym if data["signing"]
      self
    rescue StandardError
      self
    end

    def persist_settings!
      FileUtils.mkdir_p(config_dir)
      File.write(settings_path, JSON.generate("shared_password" => shared_password, "signing" => signing.to_s))
    end

    private

    def default_providers
      [
        {
          title: "OpenID Connect",
          note: nil,
          fields: [
            ["Issuer URL", base_url],
            ["Authorization endpoint", "#{base_url}/v1/authorize"],
            ["Token endpoint", "#{base_url}/v1/token"],
            ["Discovery", "#{base_url}/.well-known/openid-configuration"],
            ["Client ID", "dev-client"],
            ["Client secret", "dev-secret"]
          ]
        },
        {
          title: "OAuth2 / Auth0-style",
          note: "Exchange the code at /oauth/token, then fetch the profile at /userinfo.",
          fields: [
            ["Authorization endpoint", "#{base_url}/authorize"],
            ["Token endpoint", "#{base_url}/oauth/token"],
            ["Userinfo endpoint", "#{base_url}/userinfo"],
            ["Domain (bare, no scheme)", base_url.sub(%r{\Ahttps?://}, "")]
          ]
        },
        {
          title: "SAML (cosmetic metadata)",
          note: "Metadata is served for wiring but not cryptographically verified — see the README.",
          fields: [
            ["Metadata URL", "#{base_url}/metadata"],
            ["Email attribute", "email"]
          ]
        },
        {
          title: "AWS Cognito broker",
          note: "Point COGNITO_ENDPOINT at this server so the management API is stubbed.",
          fields: [
            ["Endpoint", base_url],
            ["Hosted UI login", "#{base_url}/login"],
            ["Token endpoint", "#{base_url}/oauth2/token"]
          ]
        }
      ]
    end

    def env_presence(*keys)
      keys.each do |key|
        value = ENV.fetch(key, nil)
        return value if value && !value.empty?
      end
      nil
    end
  end
end
