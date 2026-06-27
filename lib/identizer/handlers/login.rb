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
        emails = store.emails
        options = emails.map { |email| "<option value=\"#{escape_html(email)}\">" }.join

        html(form_html(request.script_name, carried_fields(request), emails.first.to_s, options))
      end

      def select(request)
        email = request.params["email"].to_s.strip
        password = request.params["password"].to_s
        redirect_uri = request.params["redirect_uri"].to_s
        state = request.params["state"].to_s

        unless password == config.shared_password
          return error_redirect(redirect_uri, state, "access_denied", "Invalid credentials")
        end

        unless store.emails.include?(email)
          return error_redirect(redirect_uri, state, "access_denied", "Unknown user: #{email}")
        end

        code = SecureRandom.hex(20)
        sessions[code] = authorization_for(request, email)
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

      # Hidden <input>s re-emitting the carried authorization params into /__select.
      def carried_fields(request)
        CARRIED_PARAMS.map do |name|
          value = escape_html(request.params[name].to_s)
          "<input type=\"hidden\" name=\"#{name}\" value=\"#{value}\">"
        end.join("\n              ")
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

      def form_html(prefix, hidden_fields, first_email, options)
        <<~HTML
          <!doctype html><html><head><meta charset="utf-8"><title>Identizer — Sign in</title></head>
          <body style="font-family:sans-serif;max-width:480px;margin:64px auto">
            <h2>Identizer — Sign in</h2>
            <p>Sign in as one of the configured identities. The password for every
               identity is <code>#{escape_html(config.shared_password)}</code> — use a
               wrong password or an unconfigured email to test the provider's error
               response.</p>
            <form method="get" action="#{prefix}/__select">
              #{hidden_fields}
              <input name="email" type="email" required autofocus list="identizer-emails"
                     value="#{escape_html(first_email)}" placeholder="user@example.com"
                     style="width:100%;padding:8px">
              <datalist id="identizer-emails">#{options}</datalist>
              <input name="password" type="password" required placeholder="password"
                     style="width:100%;padding:8px;margin-top:8px">
              <button type="submit" style="margin-top:16px;padding:8px 16px">Sign in</button>
            </form>
            <p style="margin-top:24px"><a href="#{prefix}/">Configure identities</a></p>
          </body></html>
        HTML
      end
    end
  end
end
