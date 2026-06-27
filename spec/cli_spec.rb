# frozen_string_literal: true

require "spec_helper"
require "identizer/cli"
require "tmpdir"

RSpec.describe Identizer::CLI do
  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  end

  def config
    Identizer::Configuration.new.tap { |c| c.config_dir = @dir }
  end

  it "parses flags onto the configuration without starting a server" do
    cli = described_class.new(%w[--port 12345 --rs256 --password secret --url-host idp.test])
    result = cli.configure(config)

    expect(result.port).to eq(12_345)
    expect(result.signing).to eq(:rs256)
    expect(result.shared_password).to eq("secret")
    expect(result.url_host).to eq("idp.test")
  end

  it "seeds a demo user on first run so login works out of the box" do
    result = described_class.new([]).configure(config)
    expect(result.identity_store.emails).to eq(["demo@example.com"])
  end

  it "skips the demo user with --no-demo" do
    result = described_class.new(["--no-demo"]).configure(config)
    expect(result.seed_identities).to be_empty
  end

  it "does not override explicitly configured identities with the demo user" do
    seeded = config
    seeded.seed_identities = [{ mail: "real@example.com" }]
    result = described_class.new([]).configure(seeded)
    expect(result.identity_store.emails).to eq(["real@example.com"])
  end

  it "applies settings previously saved from the web admin" do
    saved = config
    saved.shared_password = "fromfile"
    saved.signing = :rs256
    saved.persist_settings!

    result = described_class.new([]).configure(config)

    expect(result.shared_password).to eq("fromfile")
    expect(result.signing).to eq(:rs256)
  end
end
