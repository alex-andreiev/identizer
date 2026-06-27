# frozen_string_literal: true

module Identizer
  # Everything the provider needs to run, with sensible dev defaults. Replaces
  # the Rails.* / ENV reads of the original emulator with one explicit object.
  class Configuration
    def initialize
      @host = "127.0.0.1"
      @port = int_env("IDENTIZER_PORT", "SSO_MOCK_PORT", default: 9999)
      @tls_cert_path = env_presence("IDENTIZER_TLS_CERT", "SSO_MOCK_TLS_CERT")
      @tls_key_path = env_presence("IDENTIZER_TLS_KEY", "SSO_MOCK_TLS_KEY")
      @config_dir = ENV.fetch("IDENTIZER_CONFIG_DIR", File.join(Dir.pwd, "tmp", "identizer"))
      @shared_password = "password"
      @signing = :hs256 # :hs256 (unsigned-style parity) or :rs256 (verifiable)
      @hs256_key = "identizer-development-key"
      @scheme = "https"
      @url_host = "localhost"
      @ldap_base_dn = "dc=identizer,dc=local"
      @ldap_host = nil
      @ldap_port = optional_int_env("IDENTIZER_LDAP_PORT") # nil = LDAP listener off
      @ldaps_port = optional_int_env("IDENTIZER_LDAPS_PORT") # nil = LDAPS listener off
      @seed_identities = []
      # Optional client registry: [{ client_id:, redirect_uris:, post_logout_redirect_uris: }].
      # A client_secret may be present but is NOT verified (dev tool). Separate from
      # the apps provisioned at runtime via the Auth0 Management API.
      @clients = []
      @saml_allowed_acs = [] # optional allowlist of SAML ACS URLs ([] = allow any, dev default)
      @saml_sign_response = true # sign the SAML Response in addition to the Assertion
      @saml_encrypt_assertion = false # encrypt the assertion when an SP certificate is set
      @saml_sp_certificate = nil # SP cert (PEM) used to encrypt the assertion
      @code_ttl = 600
      @access_token_ttl = 3600
      @refresh_token_ttl = 86_400
      @request_logging = true # standalone server logs a concise request line
    end

    attr_accessor :host, :port, :tls_cert_path, :tls_key_path, :config_dir, :shared_password, :signing, :hs256_key,
                  :scheme, :url_host, :ldap_base_dn, :ldap_host, :ldap_port, :ldaps_port, :request_logging

    # Grant lifetimes (seconds), enforced by the GrantStore.
    attr_accessor :code_ttl, :access_token_ttl, :refresh_token_ttl, :saml_allowed_acs,
                  :saml_sign_response, :saml_encrypt_assertion

    # The SP certificate used to encrypt the assertion, as an OpenSSL cert
    # (accepts a PEM string or a certificate object).
    def saml_sp_certificate
      cert = @saml_sp_certificate
      return nil if cert.nil?

      cert.is_a?(OpenSSL::X509::Certificate) ? cert : OpenSSL::X509::Certificate.new(cert.to_s)
    end

    # Registered OAuth clients. Empty = accept any client_id (lenient dev default).
    attr_accessor :clients

    # When set (e.g. via `--sqlite`), the CLI swaps in the SQLite-backed directory.
    attr_accessor :sqlite_path

    # The IdP's SAML signing key + certificate, generated/persisted on first use.
    def saml_keypair
      @saml_keypair ||= begin
        require "identizer/saml/keypair"
        Saml::Keypair.load_or_generate(config_dir)
      end
    end

    # Claim -> SAML Attribute Name. Defaults to the Microsoft/WS-Fed claim URIs
    # that real SAML IdPs (Azure AD, ADFS, Okta) emit and SPs match on; the short
    # claim name is kept as the FriendlyName. Override to suit a specific SP.
    SAML_ATTRIBUTE_NAMES = {
      "email" => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "given_name" => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
      "family_name" => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
      "name" => "http://schemas.microsoft.com/identity/claims/displayname",
      "groups" => "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
    }.freeze

    def saml_attribute_names
      @saml_attribute_names ||= SAML_ATTRIBUTE_NAMES.dup
    end

    attr_writer :saml_sp_certificate, :identity_store, :base_url, :issuer, :seed_identities, :providers, :saml_keypair,
                :saml_attribute_names

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
      @providers || Providers.default(base_url)
    end

    # Open-redirect guard. Lenient (true) until clients are registered; then the
    # redirect_uri must match one registered for that client.
    def redirect_uri_allowed?(client_id, redirect_uri)
      return true if clients.empty?

      client = clients.find { |entry| entry[:client_id] == client_id }
      return false unless client

      allowed = Array(client[:redirect_uris])
      allowed.empty? || allowed.include?(redirect_uri)
    end

    # RP-initiated-logout guard, mirroring redirect_uri_allowed?.
    def post_logout_redirect_allowed?(client_id, uri)
      return true if clients.empty?

      client = clients.find { |entry| entry[:client_id] == client_id }
      return false unless client

      allowed = Array(client[:post_logout_redirect_uris])
      allowed.empty? || allowed.include?(uri)
    end

    # SAML ACS guard. Lenient until an allowlist is configured.
    def acs_allowed?(acs)
      saml_allowed_acs.empty? || saml_allowed_acs.include?(acs)
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

    def env_presence(*keys)
      keys.each do |key|
        value = ENV.fetch(key, nil)
        return value if value && !value.empty?
      end
      nil
    end

    def optional_int_env(key)
      raw = env_presence(key)
      return nil if raw.nil?

      Integer(raw)
    rescue ArgumentError
      raise ArgumentError, "#{key} must be an integer (got #{raw.inspect})"
    end

    def int_env(*keys, default:)
      raw = env_presence(*keys)
      return default if raw.nil?

      Integer(raw)
    rescue ArgumentError
      raise ArgumentError, "#{keys.first} must be an integer (got #{raw.inspect})"
    end
  end
end
