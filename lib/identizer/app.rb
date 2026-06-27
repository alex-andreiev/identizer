# frozen_string_literal: true

module Identizer
  # The Rack application. Mount it in a test harness or run it standalone via
  # Identizer::Server. It serves three surfaces: the web admin (Overview /
  # Directory / Settings / Docs), the runtime IdP endpoints, and the AWS Cognito
  # management API (requests carrying x-amz-target).
  class App
    include Responses

    Context = Struct.new(:config, :store, :minter, :sessions, :refresh_tokens, :access_tokens, :renderer)

    def initialize(config = Identizer.configuration)
      @config = config
      context = Context.new(config, config.identity_store, TokenMinter.new(config),
                            GrantStore.new, GrantStore.new, GrantStore.new, Renderer.new)
      @overview = Handlers::Overview.new(context)
      @directory = Handlers::Directory.new(context)
      @settings = Handlers::Settings.new(context)
      @docs = Handlers::Docs.new(context)
      @login = Handlers::Login.new(context)
      @cognito = Handlers::Cognito.new(context)
      @auth0 = Handlers::Auth0.new(context)
      @auth0_management = Handlers::Auth0Management.new(context)
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
      # Surface the failure to the console (this is a local dev tool) instead of
      # silently swallowing it; still return a JSON 500 to the client.
      env["rack.errors"]&.puts("[identizer] #{e.class}: #{e.message}\n  #{e.backtrace&.first(8)&.join("\n  ")}")
      json(500, { error: e.message })
    end

    private

    def route(request)
      admin(request) || idp(request) || auth0_management(request) ||
        not_found("No route for #{request.request_method} #{request.path_info}")
    end

    # Auth0 Management API: provision/deprovision applications and connections.
    def auth0_management(request)
      case [request.request_method, request.path_info]
      in ["POST", "/api/v2/clients"] then @auth0_management.create_client(request)
      in ["GET", "/api/v2/clients"] then @auth0_management.list_clients(request)
      in ["POST", "/api/v2/connections"] then @auth0_management.create_connection(request)
      in ["GET", "/api/v2/connections"] then @auth0_management.list_connections(request)
      in ["PATCH", String => path] if path.start_with?("/api/v2/clients/")
        @auth0_management.update_client(request, path.delete_prefix("/api/v2/clients/"))
      in ["DELETE", String => path] if path.start_with?("/api/v2/clients/")
        @auth0_management.delete_client(request, path.delete_prefix("/api/v2/clients/"))
      in ["PATCH", String => path] if path.start_with?("/api/v2/connections/")
        @auth0_management.update_connection(request, path.delete_prefix("/api/v2/connections/"))
      in ["DELETE", String => path] if path.start_with?("/api/v2/connections/")
        @auth0_management.delete_connection(request, path.delete_prefix("/api/v2/connections/"))
      else nil
      end
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
      in ["GET", "/metadata" | "/saml/metadata"] then @saml.metadata(request)
      in ["GET" | "POST", "/saml/sso"] then @saml.sso(request)
      in ["POST", "/saml/finish"] then @saml.finish(request)
      # Includes the Okta-style /oauth2/v1/* paths (omniauth-okta and other
      # fixed-path OAuth2 clients) alongside the canonical ones.
      in ["GET", "/login" | "/authorize" | "/v1/authorize" | "/oauth2/v1/authorize"] then @login.form(request)
      in ["GET", "/__select"] then @login.select(request)
      in ["POST", "/oauth2/token"] then @cognito.token(request)
      in ["POST", "/oauth/token"] then @auth0.token(request)
      in ["POST", "/v1/token" | "/oauth2/v1/token"] then @oidc.token(request)
      in ["GET", "/v1/logout"] then @oidc.logout(request)
      in ["GET", "/userinfo" | "/oauth2/v1/userinfo"] then @auth0.userinfo(request)
      in ["GET", "/.well-known/openid-configuration"] then @oidc.discovery
      in ["GET", "/jwks" | "/.well-known/jwks.json" | "/oauth2/v1/keys"] then @oidc.jwks
      else nil
      end
    end
  end
end
