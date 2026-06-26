# frozen_string_literal: true

module Identizer
  module Handlers
    # The interactive login surface: a form (shared by the Cognito hosted-UI,
    # Auth0 and OIDC authorize endpoints) and the selection step that mints a
    # code and redirects back to the app.
    class Login < Base
      def form(request)
        redirect_uri = escape_html(request.params["redirect_uri"].to_s)
        state = escape_html(request.params["state"].to_s)
        emails = store.emails
        first_email = emails.first.to_s
        options = emails.map { |email| "<option value=\"#{escape_html(email)}\">" }.join

        html(form_html(request.script_name, redirect_uri, state, first_email, options))
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
        sessions[code] = store.identity_for(email)
        auth_redirect(redirect_uri, state, code: code)
      end

      private

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

      def form_html(prefix, redirect_uri, state, first_email, options)
        <<~HTML
          <!doctype html><html><head><meta charset="utf-8"><title>Identizer — Sign in</title></head>
          <body style="font-family:sans-serif;max-width:480px;margin:64px auto">
            <h2>Identizer — Sign in</h2>
            <p>Sign in as one of the configured identities. The password for every
               identity is <code>#{escape_html(config.shared_password)}</code> — use a
               wrong password or an unconfigured email to test the provider's error
               response.</p>
            <form method="get" action="#{prefix}/__select">
              <input type="hidden" name="redirect_uri" value="#{redirect_uri}">
              <input type="hidden" name="state" value="#{state}">
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
