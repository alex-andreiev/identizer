# frozen_string_literal: true

module Identizer
  module Handlers
    # Auth0-style flow: the code is exchanged for an access_token (no id_token by
    # design — the original integration only verifies a JWT when one is returned
    # and a certificate is configured), then the profile is fetched at /userinfo.
    class Auth0 < Base
      def token(request)
        # The Management API authenticates with a client_credentials grant.
        if merged_params(request)["grant_type"] == "client_credentials"
          return json(200, { access_token: SecureRandom.hex(32), token_type: "Bearer", expires_in: 86_400 })
        end

        authorization = redeem_code(request) # single-use code, PKCE-checked
        return json(400, { error: "invalid_grant" }) if authorization.nil?

        # Mint a distinct access_token that /userinfo resolves to the profile.
        access_token = SecureRandom.hex(20)
        access_tokens.put(access_token, authorization, ttl: config.access_token_ttl)
        json(200, { access_token: access_token, token_type: "Bearer", expires_in: config.access_token_ttl })
      end

      def userinfo(request)
        authorization = access_tokens.get(bearer(request))
        return json(401, { error: "invalid_token" }) if authorization.nil?

        json(200, authorization.identity.to_h)
      end
    end
  end
end
