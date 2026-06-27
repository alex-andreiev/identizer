# frozen_string_literal: true

require "spec_helper"
require "tmpdir"

RSpec.describe Identizer::TLS do
  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  end

  def config(**overrides)
    Identizer::Configuration.new.tap do |c|
      c.config_dir = @dir
      overrides.each { |key, value| c.public_send("#{key}=", value) }
    end
  end

  it "generates and persists a self-signed cert when none is provided" do
    cert, key, path = described_class.resolve(config)

    expect(cert).to be_a(OpenSSL::X509::Certificate)
    expect(key).to be_a(OpenSSL::PKey::RSA)
    expect(File.exist?(path)).to be(true)
    expect(File.exist?(File.join(@dir, "key.pem"))).to be(true)
  end

  it "loads a provided cert/key pair instead of generating one" do
    _, _, cert_path = described_class.generate_self_signed(config)
    key_path = File.join(@dir, "key.pem")

    cert, _key, path = described_class.resolve(config(tls_cert_path: cert_path, tls_key_path: key_path))

    expect(path).to eq(cert_path)
    expect(cert.subject.to_s).to include("localhost")
  end
end
