# frozen_string_literal: true

module Identizer
  module Handlers
    # OpenID Connect: the authorization-code + refresh-token grants, PKCE, the
    # discovery and JWKS documents, and the end-session (logout) endpoint.
    class Oidc < Base
      def token(request)
        case request.params["grant_type"]
        when "refresh_token" then refresh(request)
        else authorization_code(request)
        end
      end

      def discovery
        json(200, minter.discovery)
      end

      def jwks
        json(200, minter.jwks)
      end

      # RP-initiated logout: bounce back to post_logout_redirect_uri if given.
      def logout(request)
        target = request.params["post_logout_redirect_uri"].to_s
        return html("<p>Signed out.</p>") if target.empty?

        state = request.params["state"]
        separator = target.include?("?") ? "&" : "?"
        location = state.to_s.empty? ? target : "#{target}#{separator}state=#{Rack::Utils.escape(state)}"
        redirect(location)
      end

      private

      def authorization_code(request)
        return json(401, { error: "invalid_client" }) unless valid_client?(request)

        authorization = consume(code_param(request))
        return json(400, { error: "invalid_grant" }) if authorization.nil?

        unless authorization.pkce_valid?(request.params["code_verifier"])
          return json(400, { error: "invalid_grant", error_description: "PKCE verification failed" })
        end

        issue(authorization)
      end

      def refresh(request)
        authorization = refresh_tokens.delete(request.params["refresh_token"])
        return json(400, { error: "invalid_grant" }) if authorization.nil?

        issue(authorization)
      end

      def issue(authorization)
        refresh_token = SecureRandom.hex(20)
        refresh_tokens[refresh_token] = authorization

        body = {
          access_token: SecureRandom.hex(20),
          id_token: minter.id_token(authorization.identity, nonce: authorization.nonce),
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: refresh_token
        }
        body[:scope] = authorization.scope unless authorization.scope.to_s.empty?
        json(200, body)
      end

      # Lenient by default: only enforced when clients are configured.
      def valid_client?(request)
        return true if config.clients.empty?

        config.clients.any? { |client| client[:client_id] == request.params["client_id"] }
      end
    end
  end
end
