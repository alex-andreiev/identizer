# frozen_string_literal: true

module Identizer
  # Registry of the bundled, read-only documentation pages shown under /docs.
  # Each slug maps to a web/views/docs/<slug>.html.erb template.
  module Docs
    PAGES = [
      { slug: "getting-started", title: "Getting started" },
      { slug: "oidc", title: "OIDC integration" },
      { slug: "cognito", title: "AWS Cognito broker" },
      { slug: "saml", title: "SAML" },
      { slug: "ldap", title: "LDAP listener" },
      { slug: "tls", title: "TLS & mkcert" },
      { slug: "troubleshooting", title: "Troubleshooting" }
    ].freeze

    def self.find(slug)
      PAGES.find { |page| page[:slug] == slug }
    end
  end
end
