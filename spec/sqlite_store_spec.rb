# frozen_string_literal: true

require "spec_helper"
require "identizer/identity_store/sqlite_store"
require "rack/test"
require "tmpdir"

RSpec.describe Identizer::IdentityStore::SqliteStore do
  subject(:store) { described_class.new(path: @path) }

  around do |example|
    Dir.mktmpdir do |dir|
      @path = File.join(dir, "dir.sqlite3")
      example.run
    end
  end

  it "seeds from the in-code seed when empty, once" do
    seeded = described_class.new(path: @path, seed: [{ mail: "seed@example.com", givenName: "Seed" }])
    expect(seeded.emails).to eq(["seed@example.com"])

    # reopening does not re-seed on top of existing rows
    reopened = described_class.new(path: @path, seed: [{ mail: "other@example.com" }])
    expect(reopened.emails).to eq(["seed@example.com"])
  end

  it "upserts, reads and deletes entries with claims preserved" do
    store.upsert("mail" => "a@example.com", "givenName" => "Al", "memberOf" => %w[admins])
    store.upsert("mail" => "a@example.com", "sn" => "Smith") # replace, keyed by mail
    store.upsert("mail" => "b@example.com")

    expect(store.emails).to contain_exactly("a@example.com", "b@example.com")
    entry = store.entries.find { |e| e.mail == "a@example.com" }
    expect(entry["sn"]).to eq("Smith")

    store.delete("a@example.com")
    expect(store.emails).to eq(["b@example.com"])
  end

  it "projects an entry to OIDC claims via identity_for" do
    store.upsert("mail" => "a@example.com", "givenName" => "Al", "sn" => "Smith")
    expect(store.identity_for("a@example.com").to_h).to include(
      "given_name" => "Al", "family_name" => "Smith"
    )
  end

  it "drives the full Rack app as the identity store" do
    store.upsert("mail" => "alice@example.com")
    config = Identizer::Configuration.new.tap { |c| c.identity_store = store }
    app = Identizer::App.new(config)

    session = Rack::Test::Session.new(Rack::MockSession.new(app))
    session.get "/__select", redirect_uri: "https://app.test/cb", state: "s",
                             email: "alice@example.com", password: "password"
    code = Rack::Utils.parse_query(URI(session.last_response.headers["location"]).query).fetch("code")
    session.post "/oauth2/token", code: code

    expect(session.last_response.status).to eq(200)
    expect(JSON.parse(session.last_response.body)).to have_key("id_token")
  end
end
