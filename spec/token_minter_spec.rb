# frozen_string_literal: true

require "spec_helper"
require "tmpdir"

RSpec.describe Identizer::TokenMinter do
  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  end

  let(:config) do
    Identizer::Configuration.new.tap { |c| c.config_dir = @dir }
  end
  let(:identity) { Identizer::Identity.new(email: "a@b.com", sub: "s1", claims: { given_name: "Al" }) }

  describe "HS256 (default)" do
    subject(:minter) { described_class.new(config) }

    it "mints an id_token decodable with the shared key carrying the claims" do
      token = minter.id_token(identity)
      payload, = JWT.decode(token, config.hs256_key, true, algorithm: "HS256")
      expect(payload).to include("email" => "a@b.com", "sub" => "s1", "given_name" => "Al")
    end

    it "stamps standard iss/aud/iat/exp claims" do
      token = minter.id_token(identity)
      payload, = JWT.decode(token, config.hs256_key, true, algorithm: "HS256")
      expect(payload).to include("iss" => config.issuer, "aud" => "identizer")
      expect(payload["exp"]).to be > payload["iat"]
    end

    it "advertises HS256 and an empty JWKS" do
      expect(minter.discovery["id_token_signing_alg_values_supported"]).to eq(["HS256"])
      expect(minter.jwks).to eq("keys" => [])
    end
  end

  describe "RS256" do
    subject(:minter) { described_class.new(config) }

    before { config.signing = :rs256 }

    it "publishes a JWKS the id_token verifies against" do
      token = minter.id_token(identity)
      jwks = minter.jwks
      payload, header = JWT.decode(token, nil, true, algorithms: ["RS256"], jwks: jwks)

      expect(header["alg"]).to eq("RS256")
      expect(header["kid"]).to eq(jwks["keys"].first[:kid])
      expect(payload).to include("email" => "a@b.com")
    end

    it "advertises RS256 in discovery" do
      expect(minter.discovery["id_token_signing_alg_values_supported"]).to eq(["RS256"])
    end

    it "persists the signing key so the JWKS is stable across instances" do
      first = described_class.new(config).jwks
      second = described_class.new(config).jwks
      expect(first).to eq(second)
    end
  end
end
