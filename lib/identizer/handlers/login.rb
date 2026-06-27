# frozen_string_literal: true

module Identizer
  module Handlers
    # The interactive login surface: a form (shared by the Cognito hosted-UI,
    # Auth0 and OIDC authorize endpoints) and the selection step that mints a
    # code and redirects back to the app.
    class Login < Base
      # The authorization-request parameters that must survive the login form.
      CARRIED_PARAMS = %w[redirect_uri state scope nonce code_challenge code_challenge_method client_id].freeze

      def form(request)
        render_login(
          title: "Identizer — Sign in", heading: "Identizer — Sign in", note: sign_in_note,
          form_method: "get", action: "#{request.script_name}/__select",
          hidden: CARRIED_PARAMS.map { |name| [name, request.params[name]] },
          config_link: "#{request.script_name}/"
        )
      end

      def select(request)
        email = request.params["email"].to_s.strip
        password = request.params["password"].to_s
        redirect_uri = request.params["redirect_uri"].to_s
        state = request.params["state"].to_s

        # Validate the redirect target FIRST — never bounce to an unregistered URI,
        # not even on the error paths below (that would be the open redirect).
        unless config.redirect_uri_allowed?(request.params["client_id"], redirect_uri)
          return notice_page("Sign-in blocked",
                             "redirect_uri <code>#{escape_html(redirect_uri)}</code> is not registered " \
                             "for this client.")
        end

        unless password == config.shared_password
          return error_redirect(redirect_uri, state, "access_denied", "Invalid credentials")
        end

        unless store.emails.include?(email)
          return error_redirect(redirect_uri, state, "access_denied", "Unknown user: #{email}")
        end

        code = SecureRandom.hex(20)
        codes.put(code, authorization_for(request, email), ttl: config.code_ttl)
        auth_redirect(redirect_uri, state, code: code)
      end

      private

      def authorization_for(request, email)
        Authorization.new(
          identity: store.identity_for(email),
          code_challenge: request.params["code_challenge"],
          code_challenge_method: request.params["code_challenge_method"],
          scope: request.params["scope"],
          nonce: request.params["nonce"],
          client_id: request.params["client_id"]
        )
      end

      def sign_in_note
        "Sign in as one of the configured identities. The password for every identity is " \
          "<code>#{escape_html(config.shared_password)}</code> — use a wrong password or an " \
          "unconfigured email to test the provider's error response."
      end

      def error_redirect(redirect_uri, state, error, description)
        auth_redirect(redirect_uri, state, error: error, error_description: description)
      end

      def auth_redirect(redirect_uri, state, params)
        query = params.merge(state: state)
                      .map { |key, value| "#{key}=#{Rack::Utils.escape(value.to_s)}" }
                      .join("&")
        separator = redirect_uri.include?("?") ? "&" : "?"

        redirect("#{redirect_uri}#{separator}#{query}")
      end
    end
  end
end
