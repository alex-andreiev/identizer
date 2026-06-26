# frozen_string_literal: true

require "spec_helper"

RSpec.describe Identizer::Identity do
  it "derives a sub from the email when none is given" do
    identity = described_class.new(email: "alice@example.com")
    expect(identity.sub).to eq("identizer|alice@example.com")
  end

  it "exposes sub, email and string-keyed claims via to_h" do
    identity = described_class.new(email: "a@b.com", sub: "s1", claims: { given_name: "Al" })
    expect(identity.to_h).to eq("sub" => "s1", "email" => "a@b.com", "given_name" => "Al")
  end

  describe ".from" do
    it "passes Identity instances through" do
      identity = described_class.new(email: "a@b.com")
      expect(described_class.from(identity)).to be(identity)
    end

    it "builds from a bare email string" do
      expect(described_class.from("a@b.com").email).to eq("a@b.com")
    end

    it "treats unknown hash keys as claims" do
      identity = described_class.from(email: "a@b.com", given_name: "Al")
      expect(identity.to_h).to include("given_name" => "Al")
    end

    it "honours an explicit claims hash" do
      identity = described_class.from(email: "a@b.com", claims: { groups: %w[admin] })
      expect(identity.to_h).to include("groups" => %w[admin])
    end
  end
end
