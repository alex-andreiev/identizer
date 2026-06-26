# frozen_string_literal: true

require "json"
require "fileutils"
require "securerandom"
require "cgi"
require "openssl"
require "base64"
require "digest"
require "rack"
require "jwt"

require_relative "identizer/version"
require_relative "identizer/identity"
require_relative "identizer/directory_entry"
require_relative "identizer/identity_store"
require_relative "identizer/configuration"
require_relative "identizer/token_minter"
require_relative "identizer/responses"
require_relative "identizer/renderer"
require_relative "identizer/docs"
require_relative "identizer/handlers/base"
require_relative "identizer/handlers/overview"
require_relative "identizer/handlers/directory"
require_relative "identizer/handlers/settings"
require_relative "identizer/handlers/docs"
require_relative "identizer/handlers/login"
require_relative "identizer/handlers/cognito"
require_relative "identizer/handlers/auth0"
require_relative "identizer/handlers/oidc"
require_relative "identizer/handlers/saml"
require_relative "identizer/app"
require_relative "identizer/tls"
require_relative "identizer/server"

# Identizer is a local identity provider for developing and testing auth/SSO
# integrations. It speaks OIDC, OAuth2 and emulates an AWS Cognito / Auth0 SSO
# broker, with a pluggable identity store.
module Identizer
  class << self
    def configure
      yield(configuration) if block_given?
      configuration
    end

    def configuration
      @configuration ||= Configuration.new
    end

    def reset_configuration!
      @configuration = Configuration.new
    end

    # Build a fresh Rack app for the given configuration (defaults to the
    # process-wide configuration).
    def app(config = configuration)
      App.new(config)
    end
  end
end
