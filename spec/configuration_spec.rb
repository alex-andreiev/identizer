# frozen_string_literal: true

require "spec_helper"

RSpec.describe Identizer::Configuration do
  subject(:config) { described_class.new }

  it "defaults to an https localhost base_url on the configured port" do
    config.port = 4321
    expect(config.base_url).to eq("https://localhost:4321")
  end

  it "defaults the issuer to the base_url" do
    expect(config.issuer).to eq(config.base_url)
  end

  it "coerces seed_identities into DirectoryEntry objects" do
    config.seed_identities = [{ email: "a@b.com" }, "c@d.com"]
    expect(config.seed_identities).to all(be_a(Identizer::DirectoryEntry))
  end

  it "exposes the LDAP base DN" do
    expect(config.ldap_base_dn).to eq("dc=identizer,dc=local")
  end

  it "raises a clear error for a non-numeric IDENTIZER_PORT" do
    original = ENV.fetch("IDENTIZER_PORT", nil)
    ENV["IDENTIZER_PORT"] = "not-a-number"
    expect { described_class.new }.to raise_error(ArgumentError, /IDENTIZER_PORT must be an integer/)
  ensure
    ENV["IDENTIZER_PORT"] = original
  end

  it "builds a default ConfigStore seeded from seed_identities" do
    config.seed_identities = [{ email: "a@b.com" }]
    expect(config.identity_store.emails).to eq(["a@b.com"])
  end

  it "reports the signing mode" do
    expect(config.rs256?).to be(false)
    config.signing = :rs256
    expect(config.rs256?).to be(true)
  end

  it "ships a default provider cheatsheet referencing the base_url" do
    titles = config.providers.map { |provider| provider[:title] }
    expect(titles).to include(a_string_matching(/OpenID Connect/))
    expect(config.providers.first[:fields].flatten).to include(config.base_url)
  end
end
