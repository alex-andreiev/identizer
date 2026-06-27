# frozen_string_literal: true

module Identizer
  # Tiny helpers for building Rack responses ([status, headers, body]).
  module Responses
    def json(status, payload)
      [status, { "content-type" => "application/json" }, [JSON.generate(payload)]]
    end

    # AWS SDK expects this content type back from the Cognito management API.
    def amz_json(payload)
      [200, { "content-type" => "application/x-amz-json-1.1" }, [JSON.generate(payload)]]
    end

    def html(body, status: 200)
      [status, { "content-type" => "text/html; charset=utf-8" }, [body]]
    end

    def xml(body, headers: {})
      [200, { "content-type" => "application/xml; charset=utf-8" }.merge(headers), [body]]
    end

    def redirect(location, status: 302)
      [status, { "location" => location }, []]
    end

    def not_found(message)
      json(404, { error: message })
    end

    def no_content
      [204, {}, []]
    end

    def escape_html(value)
      CGI.escapeHTML(value.to_s)
    end

    # A small standalone HTML page (errors/notices). `body_html` is inserted raw,
    # so callers must escape any user-controlled values they put in it.
    def notice_page(heading, body_html)
      html("<!doctype html><html><body style=\"font-family:sans-serif;max-width:480px;margin:64px auto\">" \
           "<h2>#{escape_html(heading)}</h2><p>#{body_html}</p></body></html>")
    end
  end
end
