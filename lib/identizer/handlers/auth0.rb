# frozen_string_literal: true

module Identizer
  module Handlers
    # Auth0-style flow: the code is exchanged for an access_token (no id_token by
    # design — the original integration only verifies a JWT when one is returned
    # and a certificate is configured), then the profile is fetched at /userinfo.
    class Auth0 < Base
      def token(request)
        params = merged_params(request)

        # The Management API authenticates with a client_credentials grant.
        if params["grant_type"] == "client_credentials"
          return json(200, { access_token: SecureRandom.hex(32), token_type: "Bearer", expires_in: 86_400 })
        end

        code = params["code"]
        return json(400, { error: "invalid_grant" }) if sessions[code].nil?

        # The access_token IS the code; /userinfo resolves it to the profile.
        json(200, { access_token: code, token_type: "Bearer" })
      end

      def userinfo(request)
        token = bearer(request)
        # Resolve either an OIDC/Okta access_token or the Auth0 code-as-token.
        authorization = access_tokens[token] || sessions[token]
        return json(401, { error: "invalid_token" }) if authorization.nil?

        json(200, authorization.identity.to_h)
      end
    end
  end
end
