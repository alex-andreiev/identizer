# frozen_string_literal: true

require "spec_helper"

# The OIDC/OAuth2 token surface (the bulk of the protocol behaviour), split out
# of app_spec to keep each file focused.
RSpec.describe "OIDC" do
  include_context "rack app"

  describe "token (/v1/token)" do
    it "returns an access_token and id_token" do
      code = authorize.fetch("code")
      post "/v1/token", code: code

      body = JSON.parse(last_response.body)
      expect(body).to include("access_token", "id_token", "token_type" => "Bearer")
    end

    it "accepts a JSON-encoded token request body" do
      code = authorize.fetch("code")
      post "/v1/token", JSON.generate(code: code), "CONTENT_TYPE" => "application/json"

      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to have_key("id_token")
    end
  end

  describe "PKCE" do
    def challenge_for(verifier)
      Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
    end

    it "accepts the matching S256 code_verifier" do
      verifier = "this-is-a-sufficiently-long-code-verifier-123"
      code = authorize(code_challenge: challenge_for(verifier), code_challenge_method: "S256").fetch("code")
      post "/v1/token", grant_type: "authorization_code", code: code, code_verifier: verifier

      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to include("id_token", "refresh_token")
    end

    it "rejects a wrong code_verifier" do
      verifier = "this-is-a-sufficiently-long-code-verifier-123"
      code = authorize(code_challenge: challenge_for(verifier), code_challenge_method: "S256").fetch("code")
      post "/v1/token", code: code, code_verifier: "wrong"

      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)).to include("error" => "invalid_grant")
    end

    it "enforces PKCE even when the code is redeemed at another token endpoint" do
      verifier = "this-is-a-sufficiently-long-code-verifier-123"
      code = authorize(code_challenge: challenge_for(verifier), code_challenge_method: "S256").fetch("code")
      # Redeem at the Cognito token endpoint with no verifier — must still fail.
      post "/oauth2/token", code: code
      expect(last_response.status).to eq(400)
    end
  end

  describe "id_token audience" do
    it "is set to the requesting client_id" do
      code = authorize(client_id: "my-app").fetch("code")
      post "/v1/token", code: code
      id_token = JSON.parse(last_response.body).fetch("id_token")
      payload, = JWT.decode(id_token, config.hs256_key, true, algorithm: "HS256")
      expect(payload["aud"]).to eq("my-app")
    end
  end

  describe "refresh tokens" do
    it "exchanges a refresh_token for fresh tokens and rotates it" do
      code = authorize.fetch("code")
      post "/v1/token", code: code
      refresh_token = JSON.parse(last_response.body).fetch("refresh_token")

      post "/v1/token", grant_type: "refresh_token", refresh_token: refresh_token
      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to include("id_token", "refresh_token")

      # the old refresh token is single-use
      post "/v1/token", grant_type: "refresh_token", refresh_token: refresh_token
      expect(last_response.status).to eq(400)
    end

    it "rejects an unknown refresh_token" do
      post "/v1/token", grant_type: "refresh_token", refresh_token: "nope"
      expect(last_response.status).to eq(400)
    end

    it "advertises expires_in matching the configured access_token_ttl" do
      config.access_token_ttl = 1234
      code = authorize.fetch("code")
      post "/v1/token", code: code
      expect(JSON.parse(last_response.body)).to include("expires_in" => 1234)
    end

    it "revoking an access token also invalidates the paired refresh token" do
      code = authorize.fetch("code")
      post "/v1/token", code: code
      body = JSON.parse(last_response.body)

      post "/revoke", token: body.fetch("access_token")
      post "/v1/token", grant_type: "refresh_token", refresh_token: body.fetch("refresh_token")
      expect(last_response.status).to eq(400)
    end
  end

  describe "scope + nonce" do
    it "echoes the requested scope in the token response" do
      code = authorize(scope: "openid email").fetch("code")
      post "/v1/token", code: code
      expect(JSON.parse(last_response.body)).to include("scope" => "openid email")
    end

    it "binds the nonce into the id_token" do
      code = authorize(nonce: "n-0S6_WzA2Mj").fetch("code")
      post "/v1/token", code: code
      id_token = JSON.parse(last_response.body).fetch("id_token")
      payload, = JWT.decode(id_token, config.hs256_key, true, algorithm: "HS256")
      expect(payload).to include("nonce" => "n-0S6_WzA2Mj")
    end
  end

  describe "RP-initiated logout" do
    it "redirects to post_logout_redirect_uri with state" do
      get "/v1/logout", post_logout_redirect_uri: "https://app.test/bye", state: "s1"
      expect(last_response.status).to eq(302)
      expect(last_response.headers["location"]).to eq("https://app.test/bye?state=s1")
    end

    it "shows a signed-out page without a redirect target" do
      get "/v1/logout"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("Signed out")
    end

    it "blocks an unregistered post_logout_redirect_uri when clients are configured" do
      config.clients = [{ client_id: "web", post_logout_redirect_uris: ["https://app.test/bye"] }]
      get "/v1/logout", post_logout_redirect_uri: "https://evil.test/bye", client_id: "web"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("not registered")
    end
  end

  describe "client registry" do
    before { config.clients = [{ client_id: "web" }] }

    it "rejects an unknown client_id" do
      code = authorize(client_id: "web").fetch("code")
      post "/v1/token", code: code, client_id: "evil"
      expect(last_response.status).to eq(401)
      expect(JSON.parse(last_response.body)).to include("error" => "invalid_client")
    end

    it "accepts a registered client_id" do
      code = authorize(client_id: "web").fetch("code")
      post "/v1/token", code: code, client_id: "web"
      expect(last_response.status).to eq(200)
    end

    it "blocks a redirect_uri not registered for the client (no open redirect)" do
      config.clients = [{ client_id: "web", redirect_uris: ["https://app.test/cb"] }]
      get "/__select", redirect_uri: "https://evil.test/grab", state: "s",
                       email: "alice@example.com", password: "password", client_id: "web"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("Sign-in blocked")
      expect(last_response.headers["location"]).to be_nil
    end

    it "blocks the redirect_uri even on the wrong-password error path" do
      config.clients = [{ client_id: "web", redirect_uris: ["https://app.test/cb"] }]
      get "/__select", redirect_uri: "https://evil.test/grab", state: "s",
                       email: "alice@example.com", password: "WRONG", client_id: "web"
      expect(last_response.body).to include("Sign-in blocked")
      expect(last_response.headers["location"]).to be_nil
    end
  end

  describe "token expiry" do
    it "rejects an expired access_token at userinfo" do
      config.access_token_ttl = 0
      code = authorize.fetch("code")
      post "/oauth/token", code: code
      token = JSON.parse(last_response.body).fetch("access_token")

      header "Authorization", "Bearer #{token}"
      get "/userinfo"
      expect(last_response.status).to eq(401)
    end

    it "rejects an expired authorization code at the token endpoint" do
      config.code_ttl = 0
      code = authorize.fetch("code")
      post "/v1/token", code: code
      expect(last_response.status).to eq(400)
    end
  end

  describe "Okta-style /oauth2/v1/* endpoints" do
    it "serves the authorize form" do
      get "/oauth2/v1/authorize", redirect_uri: "https://app.test/cb"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("alice@example.com")
    end

    it "exchanges the code for tokens, then resolves the profile at userinfo" do
      code = authorize.fetch("code")
      post "/oauth2/v1/token", code: code
      body = JSON.parse(last_response.body)
      expect(body).to include("access_token", "id_token")

      header "Authorization", "Bearer #{body['access_token']}"
      get "/oauth2/v1/userinfo"
      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to include("email" => "alice@example.com", "name" => "Alice Doe")
    end
  end

  describe "introspection + revocation" do
    def issue_access_token(scope: "openid email")
      code = authorize(scope: scope, client_id: "demo").fetch("code")
      post "/v1/token", code: code
      JSON.parse(last_response.body).fetch("access_token")
    end

    it "introspects an active token" do
      post "/introspect", token: issue_access_token
      expect(JSON.parse(last_response.body)).to include(
        "active" => true, "username" => "alice@example.com", "scope" => "openid email", "client_id" => "demo"
      )
    end

    it "reports an unknown token as inactive" do
      post "/introspect", token: "nope"
      expect(JSON.parse(last_response.body)).to eq("active" => false)
    end

    it "revokes a token, after which introspection is inactive" do
      token = issue_access_token
      post "/revoke", token: token
      expect(last_response.status).to eq(200)

      post "/introspect", token: token
      expect(JSON.parse(last_response.body)).to eq("active" => false)
    end
  end

  describe "discovery + JWKS" do
    it "serves the discovery document" do
      get "/.well-known/openid-configuration"
      doc = JSON.parse(last_response.body)
      expect(doc).to include("issuer" => config.issuer,
                             "end_session_endpoint" => "#{config.base_url}/v1/logout",
                             "introspection_endpoint" => "#{config.base_url}/introspect",
                             "revocation_endpoint" => "#{config.base_url}/revoke")
      expect(doc["grant_types_supported"]).to include("refresh_token")
      expect(doc["code_challenge_methods_supported"]).to include("S256")
    end

    it "serves a JWKS document" do
      get "/.well-known/jwks.json"
      expect(JSON.parse(last_response.body)).to have_key("keys")
    end
  end

  describe "RS256 mode" do
    before { config.signing = :rs256 }

    it "mints id_tokens verifiable against the published JWKS" do
      code = authorize.fetch("code")
      post "/oauth2/token", code: code
      id_token = JSON.parse(last_response.body).fetch("id_token")

      get "/.well-known/jwks.json"
      jwks = JSON.parse(last_response.body, symbolize_names: true)
      payload, = JWT.decode(id_token, nil, true, algorithms: ["RS256"], jwks: jwks)
      expect(payload).to include("email" => "alice@example.com")
    end
  end
end
