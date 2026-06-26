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
        { email: "alice@example.com", claims: { given_name: "Alice", family_name: "Doe" } }
      ]
    end
  end
  let(:app) { described_class.new(config) }

  # Drive the login form and return the parsed redirect query.
  def authorize(email: "alice@example.com", password: "password")
    get "/__select", redirect_uri: "https://app.test/cb", state: "xyz", email: email, password: password
    Rack::Utils.parse_query(URI(last_response.headers["location"]).query)
  end

  describe "dashboard" do
    it "renders the configuration page" do
      get "/"
      expect(last_response.status).to eq(200)
      expect(last_response.content_type).to start_with("text/html")
      expect(last_response.body).to include("Identizer", "alice@example.com")
    end

    it "saves edited identities and redirects" do
      post "/config", emails: "new@example.com\n  \nother@example.com"
      expect(last_response.status).to eq(302)
      expect(config.identity_store.emails).to eq(["new@example.com", "other@example.com"])
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
  end

  describe "OIDC discovery + JWKS" do
    it "serves the discovery document" do
      get "/.well-known/openid-configuration"
      expect(JSON.parse(last_response.body)).to include("issuer" => config.issuer)
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
