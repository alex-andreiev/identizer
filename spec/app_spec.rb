# frozen_string_literal: true

require "spec_helper"

RSpec.describe Identizer::App do
  include_context "rack app"

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

    it "stores custom attributes from the free-form field as claims" do
      post "/directory", mail: "carol@example.com", custom_attributes: "custom_1 = 42\ndepartment: Eng"
      entry = config.identity_store.entries.find { |e| e.mail == "carol@example.com" }
      expect(entry.to_identity.to_h).to include("custom_1" => "42", "department" => "Eng")
    end

    it "ignores reserved/standard names in custom attributes (no claim forging)" do
      post "/directory", mail: "x@example.com", givenName: "X",
                         custom_attributes: "aud = evil\nexp = 1\nsub = admin\ndepartment = ok"
      claims = config.identity_store.entries.find { |e| e.mail == "x@example.com" }.to_identity.to_h
      expect(claims).to include("department" => "ok")
      expect(claims).not_to include("aud", "exp")
      expect(claims["sub"]).to start_with("uid=") # the real DN, not "admin"
    end

    it "deletes a directory entry" do
      post "/directory/delete", mail: "alice@example.com"
      expect(last_response.status).to eq(302)
      expect(config.identity_store.emails).to eq([])
    end

    it "renames an entry without leaving a duplicate" do
      post "/directory", mail: "new-alice@example.com", original_mail: "alice@example.com", givenName: "Alice"
      expect(config.identity_store.emails).to eq(["new-alice@example.com"])
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
    it "exchanges the code for a distinct access_token and resolves the profile" do
      code = authorize.fetch("code")
      post "/oauth/token", code: code
      token = JSON.parse(last_response.body).fetch("access_token")
      expect(token).not_to eq(code) # not the raw code anymore

      header "Authorization", "Bearer #{token}"
      get "/userinfo"
      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to include("email" => "alice@example.com")
    end

    it "makes the authorization code single-use" do
      code = authorize.fetch("code")
      post "/oauth/token", code: code
      post "/oauth/token", code: code
      expect(last_response.status).to eq(400)
    end

    it "rejects userinfo without a valid token" do
      header "Authorization", "Bearer nope"
      get "/userinfo"
      expect(last_response.status).to eq(401)
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

  describe "health" do
    it "reports status + version" do
      get "/healthz"
      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to include("status" => "ok", "version" => Identizer::VERSION)
    end
  end

  describe "unknown routes" do
    it "returns a 404 JSON error" do
      get "/nope"
      expect(last_response.status).to eq(404)
      expect(JSON.parse(last_response.body)).to include("error")
    end
  end
end
