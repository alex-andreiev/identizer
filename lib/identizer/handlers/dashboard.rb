# frozen_string_literal: true

module Identizer
  module Handlers
    # The configuration dashboard at "/": edit the directory of sign-in
    # identities and copy the per-protocol setup values.
    class Dashboard < Base
      def index(request)
        html(dashboard_html(request.script_name))
      end

      def save(request)
        emails = request.params["emails"].to_s.split("\n").map(&:strip).reject(&:empty?)
        store.replace_emails(emails) if store.respond_to?(:replace_emails)

        redirect("#{request.script_name}/")
      end

      private

      def dashboard_html(prefix)
        <<~HTML
          <!doctype html><html><head><meta charset="utf-8"><title>Identizer</title>
          <style>
            body{font-family:sans-serif;max-width:760px;margin:48px auto;padding:0 16px}
            textarea{width:100%;height:140px;padding:8px;font-family:monospace}
            .provider{border:1px solid #ddd;border-radius:8px;padding:12px 16px;margin:12px 0}
            .field{display:flex;gap:8px;align-items:center;margin:6px 0}
            .field label{width:200px;color:#555}
            .field input{flex:1;padding:6px;font-family:monospace}
            button{padding:6px 12px;cursor:pointer}
          </style></head>
          <body>
            <h1>Identizer</h1>
            <p>A local identity provider for developing and testing auth/SSO integrations.</p>

            <h2>Configured identities</h2>
            <p>One email per line. These are the identities the login form accepts
               (password for all: <code>#{escape_html(config.shared_password)}</code>).</p>
            <form method="post" action="#{prefix}/config">
              <textarea name="emails" placeholder="user@example.com">#{escape_html(store.emails.join("\n"))}</textarea>
              <p><button type="submit">Save</button></p>
            </form>

            <h2>SAML metadata</h2>
            <div class="field">
              <label>Metadata URL</label>
              <input readonly value="#{escape_html(config.base_url)}/metadata">
              <button type="button" data-copy>Copy</button>
            </div>
            <p><a href="#{prefix}/metadata?download=1" download="identizer-metadata.xml">Download metadata.xml</a></p>

            <h2>Provider setup cheatsheet</h2>
            #{config.providers.map { |provider| provider_block(provider) }.join}

            <script>
              document.querySelectorAll("[data-copy]").forEach(function(button){
                button.addEventListener("click", function(){
                  navigator.clipboard.writeText(button.previousElementSibling.value)
                })
              })
            </script>
          </body></html>
        HTML
      end

      def provider_block(provider)
        fields = provider[:fields].map do |label, value|
          <<~FIELD
            <div class="field">
              <label>#{escape_html(label)}</label>
              <input readonly value="#{escape_html(value)}">
              <button type="button" data-copy>Copy</button>
            </div>
          FIELD
        end.join

        note = provider[:note] ? "<p>#{escape_html(provider[:note])}</p>" : ""
        "<div class=\"provider\"><h3>#{escape_html(provider[:title])}</h3>#{note}#{fields}</div>"
      end
    end
  end
end
