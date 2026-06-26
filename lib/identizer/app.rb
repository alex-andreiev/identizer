# frozen_string_literal: true

module Identizer
  # The Rack application. Mount it in a test harness or run it standalone via
  # Identizer::Server. Two surfaces are dispatched: the AWS Cognito management
  # API (requests carrying x-amz-target) and the runtime IdP endpoints.
  class App
    include Responses

    Context = Struct.new(:config, :store, :minter, :sessions)

    def initialize(config = Identizer.configuration)
      @config = config
      context = Context.new(config, config.identity_store, TokenMinter.new(config), {})
      @login = Handlers::Login.new(context)
      @cognito = Handlers::Cognito.new(context)
      @auth0 = Handlers::Auth0.new(context)
      @oidc = Handlers::Oidc.new(context)
      @saml = Handlers::Saml.new(context)
      @dashboard = Handlers::Dashboard.new(context)
    end

    def call(env)
      request = Rack::Request.new(env)
      target = env["HTTP_X_AMZ_TARGET"]

      if target
        @cognito.management_api(target, request)
      else
        route(request)
      end
    rescue StandardError => e
      json(500, { error: e.message })
    end

    private

    def route(request)
      case [request.request_method, request.path_info]
      in ["GET", "/"]
        @dashboard.index(request)
      in ["POST", "/config"]
        @dashboard.save(request)
      in ["GET", "/metadata"]
        @saml.metadata(request)
      in ["GET", "/login" | "/authorize" | "/v1/authorize"]
        @login.form(request)
      in ["GET", "/__select"]
        @login.select(request)
      in ["POST", "/oauth2/token"]
        @cognito.token(request)
      in ["POST", "/oauth/token"]
        @auth0.token(request)
      in ["POST", "/v1/token"]
        @oidc.token(request)
      in ["GET", "/userinfo"]
        @auth0.userinfo(request)
      in ["GET", "/.well-known/openid-configuration"]
        @oidc.discovery
      in ["GET", "/jwks" | "/.well-known/jwks.json"]
        @oidc.jwks
      else
        not_found("No route for #{request.request_method} #{request.path_info}")
      end
    end
  end
end
