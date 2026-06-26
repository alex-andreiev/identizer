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

    def escape_html(value)
      CGI.escapeHTML(value.to_s)
    end
  end
end
