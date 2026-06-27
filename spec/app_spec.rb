# frozen_string_literal: true

require "spec_helper"
require "rack/test"
require "tmpdir"

RSpec.describe Identizer::App do
  include Rack::Test::Methods

  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  end

  let(:config) do
    Identizer::Configuration.new.tap do |c|
      c.config_dir = @dir
      c.seed_identities = [
        { mail: "alice@example.com", givenName: "Alice", sn: "Doe" }
      ]
    end
  end
  let(:app) { described_class.new(config) }

  # Drive the login selection step and return the parsed redirect query. Extra
  # authorization params (scope, nonce, code_challenge, ...) pass straight through.
  def authorize(email: "alice@example.com", password: "password", **extra)
    params = { redirect_uri: "https://app.test/cb", state: "xyz", email: email, password: password }
    get "/__select", params.merge(extra)
    Rack::Utils.parse_query(URI(last_response.headers["location"]).query)
  end

  describe "web admin" do
    it "renders the overview" do
      get "/"
      expect(last_response.status).to eq(200)
      expect(last_response.content_type).to start_with("text/html")
      expect(last_response.body).to include("Identizer", "Overview", config.base_url)
    end

    it "lists directory entries" do
      get "/directory"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("alice@example.com", "uid=alice,ou=people")
    end

    it "creates a directory entry from LDAP attributes" do
      post "/directory", mail: "bob@example.com", givenName: "Bob", sn: "Jones", memberOf: "admins\nstaff"
      expect(last_response.status).to eq(302)
      entry = config.identity_store.entries.find { |e| e.mail == "bob@example.com" }
      expect(entry.groups).to eq(%w[admins staff])
      expect(entry.to_identity.to_h).to include("given_name" => "Bob", "family_name" => "Jones")
    end

    it "deletes a directory entry" do
      post "/directory/delete", mail: "alice@example.com"
      expect(last_response.status).to eq(302)
      expect(config.identity_store.emails).to eq([])
    end

    it "edits settings and persists them" do
      post "/settings", shared_password: "hunter2", signing: "rs256"
      expect(last_response.status).to eq(302)
      expect(config.shared_password).to eq("hunter2")
      expect(config.signing).to eq(:rs256)
      expect(JSON.parse(File.read(config.settings_path))).to include("shared_password" => "hunter2")
    end

    it "serves the docs index and a doc page" do
      get "/docs"
      expect(last_response.body).to include("Getting started", "Cheatsheet: Cognito-brokered app")
      get "/docs/oidc"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("OIDC")
      get "/docs/broker-app"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("OIDC issuer URL", "#{config.base_url}/saml/sso")
      get "/docs/nope"
      expect(last_response.status).to eq(404)
    end
  end

  describe "login form" do
    %w[/login /authorize /v1/authorize].each do |path|
      it "is served at #{path} with the identity datalist" do
        get path, redirect_uri: "https://app.test/cb"
        expect(last_response.status).to eq(200)
        expect(last_response.body).to include("alice@example.com")
      end
    end
  end

  describe "authorize -> code" do
    it "redirects back with a code on valid credentials" do
      params = authorize
      expect(params).to include("code", "state" => "xyz")
    end

    it "redirects with access_denied on a wrong password" do
      params = authorize(password: "nope")
      expect(params).to include("error" => "access_denied")
      expect(params).not_to include("code")
    end

    it "redirects with access_denied for an unconfigured email" do
      params = authorize(email: "stranger@example.com")
      expect(params).to include("error" => "access_denied")
    end
  end

  describe "Cognito hosted-UI token (/oauth2/token)" do
    it "exchanges a code for a signed id_token" do
      code = authorize.fetch("code")
      post "/oauth2/token", code: code

      expect(last_response.status).to eq(200)
      body = JSON.parse(last_response.body)
      payload, = JWT.decode(body["id_token"], config.hs256_key, true, algorithm: "HS256")
      expect(payload).to include("email" => "alice@example.com", "given_name" => "Alice")
    end

    it "rejects an unknown code" do
      post "/oauth2/token", code: "bogus"
      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)).to eq("error" => "invalid_grant")
    end

    it "rejects a replayed code" do
      code = authorize.fetch("code")
      post "/oauth2/token", code: code
      post "/oauth2/token", code: code
      expect(last_response.status).to eq(400)
    end
  end

  describe "Auth0 flow (/oauth/token + /userinfo)" do
    it "returns the code as access_token and resolves the profile" do
      code = authorize.fetch("code")
      post "/oauth/token", code: code
      expect(JSON.parse(last_response.body)).to include("access_token" => code)

      header "Authorization", "Bearer #{code}"
      get "/userinfo"
      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to include("email" => "alice@example.com")
    end

    it "rejects userinfo without a valid token" do
      header "Authorization", "Bearer nope"
      get "/userinfo"
      expect(last_response.status).to eq(401)
    end
  end

  describe "OIDC flow (/v1/token)" do
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

  describe "OIDC: PKCE" do
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
  end

  describe "OIDC: refresh tokens" do
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
  end

  describe "OIDC: scope + nonce" do
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

  describe "OIDC: RP-initiated logout" do
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
  end

  describe "OIDC: client registry" do
    before { config.clients = [{ client_id: "web" }] }

    it "rejects an unknown client_id" do
      code = authorize.fetch("code")
      post "/v1/token", code: code, client_id: "evil"
      expect(last_response.status).to eq(401)
      expect(JSON.parse(last_response.body)).to include("error" => "invalid_client")
    end

    it "accepts a registered client_id" do
      code = authorize.fetch("code")
      post "/v1/token", code: code, client_id: "web"
      expect(last_response.status).to eq(200)
    end
  end

  describe "Okta-style OAuth2 endpoints" do
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

  describe "OIDC discovery + JWKS" do
    it "serves the discovery document" do
      get "/.well-known/openid-configuration"
      doc = JSON.parse(last_response.body)
      expect(doc).to include("issuer" => config.issuer,
                             "end_session_endpoint" => "#{config.base_url}/v1/logout")
      expect(doc["grant_types_supported"]).to include("refresh_token")
      expect(doc["code_challenge_methods_supported"]).to include("S256")
    end

    it "serves a JWKS document" do
      get "/.well-known/jwks.json"
      expect(JSON.parse(last_response.body)).to have_key("keys")
    end
  end

  describe "SAML metadata" do
    it "serves XML metadata" do
      get "/metadata"
      expect(last_response.content_type).to start_with("application/xml")
      expect(last_response.body).to include("EntityDescriptor", "#{config.base_url}/metadata")
    end

    it "offers a download with a filename" do
      get "/metadata", download: "1"
      expect(last_response.headers["content-disposition"]).to include("identizer-metadata.xml")
    end
  end

  describe "Cognito management API (x-amz-target)" do
    def management(operation, body = {})
      post "/", JSON.generate(body),
           "CONTENT_TYPE" => "application/x-amz-json-1.1",
           "HTTP_X_AMZ_TARGET" => "AWSCognitoIdentityProviderService.#{operation}"
      JSON.parse(last_response.body)
    end

    it "stubs CreateUserPoolClient with a client id + secret" do
      payload = management("CreateUserPoolClient", "ClientName" => "web")
      expect(payload["UserPoolClient"]).to include("ClientId", "ClientSecret", "ClientName" => "web")
      expect(last_response.content_type).to eq("application/x-amz-json-1.1")
    end

    it "stubs CreateIdentityProvider echoing the name and type" do
      payload = management("CreateIdentityProvider", "ProviderName" => "okta", "ProviderType" => "SAML")
      expect(payload["IdentityProvider"]).to eq("ProviderName" => "okta", "ProviderType" => "SAML")
    end

    it "returns an empty provider list" do
      expect(management("ListIdentityProviders")).to eq("Providers" => [])
    end

    it "is idempotent for unknown operations" do
      expect(management("DeleteIdentityProvider")).to eq({})
    end
  end

  describe "unknown routes" do
    it "returns a 404 JSON error" do
      get "/nope"
      expect(last_response.status).to eq(404)
      expect(JSON.parse(last_response.body)).to include("error")
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
