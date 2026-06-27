# frozen_string_literal: true

module Identizer
  module Handlers
    # Auth0-style flow: the code is exchanged for an access_token (no id_token by
    # design — the original integration only verifies a JWT when one is returned
    # and a certificate is configured), then the profile is fetched at /userinfo.
    class Auth0 < Base
      def token(request)
        code = code_param(request)
        return json(400, { error: "invalid_grant" }) if sessions[code].nil?

        # The access_token IS the code; /userinfo resolves it to the profile.
        json(200, { access_token: code, token_type: "Bearer" })
      end

      def userinfo(request)
        authorization = sessions[bearer(request)]
        return json(401, { error: "invalid_token" }) if authorization.nil?

        json(200, authorization.identity.to_h)
      end
    end
  end
end
