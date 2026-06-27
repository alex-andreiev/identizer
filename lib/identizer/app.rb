# frozen_string_literal: true

module Identizer
  # The Rack application. Mount it in a test harness or run it standalone via
  # Identizer::Server. It serves three surfaces: the web admin (Overview /
  # Directory / Settings / Docs), the runtime IdP endpoints, and the AWS Cognito
  # management API (requests carrying x-amz-target).
  class App
    include Responses

    Context = Struct.new(:config, :store, :minter, :sessions, :refresh_tokens, :renderer)

    def initialize(config = Identizer.configuration)
      @config = config
      context = Context.new(config, config.identity_store, TokenMinter.new(config), {}, {}, Renderer.new)
      @overview = Handlers::Overview.new(context)
      @directory = Handlers::Directory.new(context)
      @settings = Handlers::Settings.new(context)
      @docs = Handlers::Docs.new(context)
      @login = Handlers::Login.new(context)
      @cognito = Handlers::Cognito.new(context)
      @auth0 = Handlers::Auth0.new(context)
      @oidc = Handlers::Oidc.new(context)
      @saml = Handlers::Saml.new(context)
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
      admin(request) || idp(request) || not_found("No route for #{request.request_method} #{request.path_info}")
    end

    # Web admin surface.
    def admin(request)
      case [request.request_method, request.path_info]
      in ["GET", "/"] then @overview.index(request)
      in ["GET", "/directory"] then @directory.index(request)
      in ["POST", "/directory"] then @directory.create(request)
      in ["POST", "/directory/delete"] then @directory.destroy(request)
      in ["GET", "/settings"] then @settings.show(request)
      in ["POST", "/settings"] then @settings.update(request)
      in ["GET", "/docs"] then @docs.index(request)
      in ["GET", String => path] if path.start_with?("/docs/")
        @docs.show(request, path.delete_prefix("/docs/"))
      else nil
      end
    end

    # Runtime IdP + protocol surface.
    def idp(request)
      case [request.request_method, request.path_info]
      in ["GET", "/metadata"] then @saml.metadata(request)
      in ["GET", "/login" | "/authorize" | "/v1/authorize"] then @login.form(request)
      in ["GET", "/__select"] then @login.select(request)
      in ["POST", "/oauth2/token"] then @cognito.token(request)
      in ["POST", "/oauth/token"] then @auth0.token(request)
      in ["POST", "/v1/token"] then @oidc.token(request)
      in ["GET", "/v1/logout"] then @oidc.logout(request)
      in ["GET", "/userinfo"] then @auth0.userinfo(request)
      in ["GET", "/.well-known/openid-configuration"] then @oidc.discovery
      in ["GET", "/jwks" | "/.well-known/jwks.json"] then @oidc.jwks
      else nil
      end
    end
  end
end
