# frozen_string_literal: true

module Identizer
  module Handlers
    # OpenID Connect: code exchange returns both an access_token and a signed
    # id_token, plus the discovery and JWKS documents real OIDC clients fetch.
    class Oidc < Base
      def token(request)
        identity = consume(code_param(request))
        return json(400, { error: "invalid_grant" }) if identity.nil?

        json(200, {
               access_token: SecureRandom.hex(20),
               id_token: minter.id_token(identity),
               token_type: "Bearer"
             })
      end

      def discovery
        json(200, minter.discovery)
      end

      def jwks
        json(200, minter.jwks)
      end
    end
  end
end
