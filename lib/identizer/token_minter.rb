# frozen_string_literal: true

module Identizer
  # Mints id_tokens and serves the OIDC discovery + JWKS documents.
  #
  # Two signing modes:
  #   :hs256 (default) — a shared symmetric key. Matches the original emulator's
  #     "consumers don't verify" behaviour; simplest for local dev.
  #   :rs256 — an RSA keypair (persisted under config_dir) with a published JWKS,
  #     so real OIDC clients that DO verify signatures work out of the box.
  class TokenMinter
    def initialize(config)
      @config = config
    end

    def id_token(identity, nonce: nil, audience: nil)
      payload = payload(identity, nonce: nonce, audience: audience)
      if @config.rs256?
        JWT.encode(payload, rsa_key, "RS256", { kid: jwk.kid })
      else
        JWT.encode(payload, @config.hs256_key, "HS256")
      end
    end

    def payload(identity, nonce: nil, audience: nil)
      now = Time.now.to_i
      claims = {
        "iss" => @config.issuer,
        # Audience is the requesting client_id when known, so OIDC clients that
        # validate `aud == client_id` accept the token; falls back to a constant.
        "aud" => audience.to_s.empty? ? "identizer" : audience,
        "iat" => now,
        "exp" => now + 3600
      }
      claims["nonce"] = nonce unless nonce.to_s.empty?
      claims.merge(identity.to_h)
    end

    def jwks
      return { "keys" => [] } unless @config.rs256?

      { "keys" => [jwk.export] }
    end

    def discovery
      base = @config.base_url
      {
        "issuer" => @config.issuer,
        "authorization_endpoint" => "#{base}/v1/authorize",
        "token_endpoint" => "#{base}/v1/token",
        "userinfo_endpoint" => "#{base}/userinfo",
        "jwks_uri" => "#{base}/.well-known/jwks.json",
        "introspection_endpoint" => "#{base}/introspect",
        "revocation_endpoint" => "#{base}/revoke",
        "end_session_endpoint" => "#{base}/v1/logout",
        "response_types_supported" => ["code"],
        "grant_types_supported" => %w[authorization_code refresh_token],
        "code_challenge_methods_supported" => %w[S256 plain],
        "subject_types_supported" => ["public"],
        "id_token_signing_alg_values_supported" => [@config.rs256? ? "RS256" : "HS256"],
        "scopes_supported" => %w[openid email profile]
      }
    end

    private

    def jwk
      @jwk ||= JWT::JWK.new(rsa_key)
    end

    def rsa_key
      @rsa_key ||= load_or_generate_rsa_key
    end

    # Persist the signing key so the JWKS stays stable across restarts.
    def load_or_generate_rsa_key
      path = File.join(@config.config_dir, "signing_key.pem")
      return OpenSSL::PKey::RSA.new(File.read(path)) if File.exist?(path)

      key = OpenSSL::PKey::RSA.new(2048)
      FileUtils.mkdir_p(@config.config_dir)
      File.write(path, key.to_pem)
      File.chmod(0o600, path)
      key
    end
  end
end
