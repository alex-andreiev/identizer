# frozen_string_literal: true

require "spec_helper"
require "tmpdir"

RSpec.describe Identizer::IdentityStore::ConfigStore do
  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  end

  let(:path) { File.join(@dir, "config.json") }

  it "falls back to the in-code seed until the file has entries" do
    store = described_class.new(path: path, seed: [{ email: "seed@example.com" }])
    expect(store.emails).to eq(["seed@example.com"])
  end

  it "persists and reads back emails edited through the dashboard" do
    store = described_class.new(path: path)
    store.replace_emails(["a@example.com", "b@example.com"])

    expect(described_class.new(path: path).emails).to eq(["a@example.com", "b@example.com"])
  end

  it "prefers persisted identities over the seed" do
    store = described_class.new(path: path, seed: [{ email: "seed@example.com" }])
    store.replace_emails(["real@example.com"])
    expect(store.emails).to eq(["real@example.com"])
  end

  it "reads the legacy {emails: [...]} file shape" do
    File.write(path, JSON.generate("emails" => ["legacy@example.com"]))
    expect(described_class.new(path: path).emails).to eq(["legacy@example.com"])
  end

  it "returns nil identity for a blank email" do
    expect(described_class.new(path: path).identity_for(" ")).to be_nil
  end

  it "synthesises an identity for an email not in the directory" do
    store = described_class.new(path: path, seed: [{ email: "known@example.com" }])
    identity = store.identity_for("stranger@example.com")
    expect(identity.email).to eq("stranger@example.com")
  end

  it "returns the configured identity (with claims) for a known email" do
    store = described_class.new(path: path, seed: [{ email: "known@example.com", given_name: "Known" }])
    expect(store.identity_for("known@example.com").to_h).to include("given_name" => "Known")
  end

  it "survives a corrupt config file by returning the seed" do
    File.write(path, "{ not json")
    store = described_class.new(path: path, seed: [{ email: "seed@example.com" }])
    expect(store.emails).to eq(["seed@example.com"])
  end
end
