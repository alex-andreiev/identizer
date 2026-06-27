# frozen_string_literal: true

module Identizer
  # The default provider cheatsheet rendered on the dashboard. Kept out of
  # Configuration so the config object stays about settings, not view copy.
  module Providers
    module_function

    def default(base_url)
      [
        {
          title: "OpenID Connect",
          note: nil,
          fields: [
            ["Issuer URL", base_url],
            ["Authorization endpoint", "#{base_url}/v1/authorize"],
            ["Token endpoint", "#{base_url}/v1/token"],
            ["Discovery", "#{base_url}/.well-known/openid-configuration"],
            ["Client ID", "dev-client"],
            ["Client secret", "dev-secret"]
          ]
        },
        {
          title: "OAuth2 / Auth0-style",
          note: "Exchange the code at /oauth/token, then fetch the profile at /userinfo.",
          fields: [
            ["Authorization endpoint", "#{base_url}/authorize"],
            ["Token endpoint", "#{base_url}/oauth/token"],
            ["Userinfo endpoint", "#{base_url}/userinfo"],
            ["Domain (bare, no scheme)", base_url.sub(%r{\Ahttps?://}, "")]
          ]
        },
        {
          title: "SAML 2.0",
          note: "A real signed IdP. Point your SP at the SSO endpoint and metadata below.",
          fields: [
            ["Metadata URL", "#{base_url}/metadata"],
            ["SSO URL (Redirect/POST)", "#{base_url}/saml/sso"],
            ["NameID", "emailAddress"]
          ]
        },
        {
          title: "AWS Cognito broker",
          note: "Point COGNITO_ENDPOINT at this server so the management API is stubbed.",
          fields: [
            ["Endpoint", base_url],
            ["Hosted UI login", "#{base_url}/login"],
            ["Token endpoint", "#{base_url}/oauth2/token"]
          ]
        }
      ]
    end
  end
end
