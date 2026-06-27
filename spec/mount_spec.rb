# frozen_string_literal: true

require "spec_helper"

# Identizer must work both standalone and mounted inside another Rack app at a
# sub-path. When mounted, internal navigation must honour SCRIPT_NAME.
RSpec.describe "mounted under a sub-path" do
  include_context "rack app"

  let(:app) do
    inner = Identizer::App.new(config)
    Rack::Builder.new { map("/idp") { run inner } }.to_app
  end

  it "serves the overview at the mount point" do
    get "/idp/"
    expect(last_response.status).to eq(200)
    expect(last_response.body).to include("Identizer")
  end

  it "points the nav and directory form at the mounted paths" do
    get "/idp/"
    expect(last_response.body).to include('href="/idp/directory"')

    get "/idp/directory"
    expect(last_response.body).to include('action="/idp/directory"')
  end

  it "points the login form at the mounted select path" do
    get "/idp/login", redirect_uri: "https://app.test/cb"
    expect(last_response.body).to include('action="/idp/__select"')
  end

  it "completes the authorize -> token round trip under the mount" do
    get "/idp/__select", redirect_uri: "https://app.test/cb", state: "s", email: "alice@example.com",
                         password: "password"
    code = Rack::Utils.parse_query(URI(last_response.headers["location"]).query).fetch("code")

    post "/idp/oauth2/token", code: code
    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)).to have_key("id_token")
  end
end
