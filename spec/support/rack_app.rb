# frozen_string_literal: true

require "rack/test"
require "tmpdir"
require "uri"

# Shared rack-test setup: a fresh app over a temp config dir, seeded with one
# directory entry, plus an `authorize` helper that drives the login step.
RSpec.shared_context "rack app" do
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
      c.seed_identities = [{ mail: "alice@example.com", givenName: "Alice", sn: "Doe" }]
    end
  end
  let(:app) { Identizer::App.new(config) }

  # Drive the login selection step and return the parsed redirect query. Extra
  # authorization params (scope, nonce, code_challenge, ...) pass straight through.
  def authorize(email: "alice@example.com", password: "password", **extra)
    params = { redirect_uri: "https://app.test/cb", state: "xyz", email: email, password: password }
    get "/__select", params.merge(extra)
    Rack::Utils.parse_query(URI(last_response.headers["location"]).query)
  end
end
