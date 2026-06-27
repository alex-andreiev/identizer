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
