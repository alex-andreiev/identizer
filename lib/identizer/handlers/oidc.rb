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

      # RFC 7662 token introspection (access or refresh token).
      def introspect(request)
        token = merged_params(request)["token"]
        authorization = token && (access_tokens.get(token) || refresh_tokens.get(token))
        return json(200, { active: false }) if authorization.nil?

        identity = authorization.identity
        json(200, {
          active: true, sub: identity.sub, username: identity.email,
          scope: authorization.scope, client_id: authorization.client_id, token_type: "Bearer"
        }.compact)
      end

      # RFC 7009 token revocation: revoke the submitted token AND its paired
      # access/refresh token. Always 200, even for unknown tokens.
      def revoke(request)
        token = merged_params(request)["token"]
        authorization = token && (access_tokens.get(token) || refresh_tokens.get(token))
        if authorization
          access_tokens.take(authorization.access_token)
          refresh_tokens.take(authorization.refresh_token)
        end
        if token
          access_tokens.take(token)
          refresh_tokens.take(token)
        end
        json(200, {})
      end

      # RP-initiated logout: bounce back to post_logout_redirect_uri if given and allowed.
      def logout(request)
        target = request.params["post_logout_redirect_uri"].to_s
        return html("<p>Signed out.</p>") if target.empty?
        unless config.post_logout_redirect_allowed?(request.params["client_id"], target)
          return html("<p>Signed out. (post_logout_redirect_uri is not registered)</p>")
        end

        state = request.params["state"]
        separator = target.include?("?") ? "&" : "?"
        location = state.to_s.empty? ? target : "#{target}#{separator}state=#{Rack::Utils.escape(state)}"
        redirect(location)
      end

      private

      def authorization_code(request)
        return json(401, { error: "invalid_client" }) unless valid_client?(request)

        authorization = redeem_code(request)
        return json(400, { error: "invalid_grant", error_description: "bad code or PKCE" }) if authorization.nil?

        issue(authorization)
      end

      def refresh(request)
        authorization = refresh_tokens.take(request.params["refresh_token"]) # single-use, rotated
        return json(400, { error: "invalid_grant" }) if authorization.nil?

        issue(authorization)
      end

      def issue(authorization)
        access_token = SecureRandom.hex(20)
        refresh_token = SecureRandom.hex(20)
        # Record the pair so revoking one revokes the other (RFC 7009).
        authorization.access_token = access_token
        authorization.refresh_token = refresh_token
        access_tokens.put(access_token, authorization, ttl: config.access_token_ttl) # /userinfo resolves it
        refresh_tokens.put(refresh_token, authorization, ttl: config.refresh_token_ttl)

        body = {
          access_token: access_token,
          id_token: minter.id_token(authorization.identity, nonce: authorization.nonce,
                                                            audience: authorization.client_id),
          token_type: "Bearer",
          expires_in: config.access_token_ttl,
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
