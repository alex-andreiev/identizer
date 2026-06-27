# frozen_string_literal: true

require "spec_helper"
require "rack/test"

# Emulated Auth0 Management API: the create/delete-application flow a brokering
# app drives when provisioning an SSO provider.
RSpec.describe "Auth0 Management API" do
  include Rack::Test::Methods

  let(:app) { Identizer::App.new(Identizer::Configuration.new) }

  def post_json(path, body)
    post path, JSON.generate(body), "CONTENT_TYPE" => "application/json"
    JSON.parse(last_response.body) unless last_response.body.empty?
  end

  describe "management token" do
    it "issues an access_token for the client_credentials grant" do
      post "/oauth/token", grant_type: "client_credentials", client_id: "x",
                           client_secret: "y", audience: "https://idp/api/v2/"
      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to include("access_token", "token_type" => "Bearer")
    end
  end

  describe "clients" do
    it "creates a client with a generated id + secret, echoing the payload" do
      client = post_json("/api/v2/clients", name: "Back-1", app_type: "regular_web")
      expect(last_response.status).to eq(201)
      expect(client).to include("name" => "Back-1", "app_type" => "regular_web")
      expect(client["client_id"]).to be_a(String)
      expect(client["client_secret"]).to be_a(String)
    end

    it "lists then deletes a client" do
      id = post_json("/api/v2/clients", name: "Front-1", app_type: "spa")["client_id"]
      get "/api/v2/clients"
      expect(JSON.parse(last_response.body).map { |c| c["client_id"] }).to include(id)

      delete "/api/v2/clients/#{id}"
      expect(last_response.status).to eq(204)
      get "/api/v2/clients"
      expect(JSON.parse(last_response.body).map { |c| c["client_id"] }).not_to include(id)
    end
  end

  describe "connections" do
    it "creates a SAML connection echoing strategy/options and returns an id" do
      connection = post_json("/api/v2/connections",
                             strategy: "samlp", name: "App-1",
                             options: { metadataUrl: "https://idp/metadata" })
      expect(last_response.status).to eq(201)
      expect(connection).to include("strategy" => "samlp", "name" => "App-1")
      expect(connection["id"]).to start_with("con_")
      expect(connection.dig("options", "metadataUrl")).to eq("https://idp/metadata")
    end

    it "updates and deletes a connection" do
      id = post_json("/api/v2/connections", strategy: "samlp", name: "App-2")["id"]

      patch "/api/v2/connections/#{id}", JSON.generate(display_name: "Renamed"), "CONTENT_TYPE" => "application/json"
      expect(JSON.parse(last_response.body)).to include("display_name" => "Renamed")

      delete "/api/v2/connections/#{id}"
      expect(last_response.status).to eq(204)
    end
  end

  describe "full provision -> deprovision flow" do
    it "creates two clients + a connection, then deletes them all" do
      back = post_json("/api/v2/clients", name: "Back-1", app_type: "regular_web")["client_id"]
      front = post_json("/api/v2/clients", name: "Front-1", app_type: "spa")["client_id"]
      connection = post_json("/api/v2/connections",
                             strategy: "samlp", name: "App-1",
                             enabled_clients: [back, front])["id"]

      delete "/api/v2/connections/#{connection}"
      delete "/api/v2/clients/#{back}"
      delete "/api/v2/clients/#{front}"

      get "/api/v2/clients"
      expect(JSON.parse(last_response.body)).to be_empty
      get "/api/v2/connections"
      expect(JSON.parse(last_response.body)).to be_empty
    end
  end
end
