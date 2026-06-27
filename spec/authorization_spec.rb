# frozen_string_literal: true

require "spec_helper"

RSpec.describe Identizer::Authorization do
  let(:identity) { Identizer::Identity.new(email: "a@b.com") }

  it "passes PKCE when no challenge was issued" do
    auth = described_class.new(identity: identity)
    expect(auth.pkce_valid?(nil)).to be(true)
  end

  it "verifies an S256 challenge" do
    verifier = "a-code-verifier-string-of-reasonable-length"
    challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
    auth = described_class.new(identity: identity, code_challenge: challenge, code_challenge_method: "S256")

    expect(auth.pkce_valid?(verifier)).to be(true)
    expect(auth.pkce_valid?("nope")).to be(false)
  end

  it "verifies a plain challenge" do
    auth = described_class.new(identity: identity, code_challenge: "abc", code_challenge_method: "plain")
    expect(auth.pkce_valid?("abc")).to be(true)
    expect(auth.pkce_valid?("xyz")).to be(false)
  end
end
