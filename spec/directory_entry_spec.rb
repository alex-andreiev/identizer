# frozen_string_literal: true

require "spec_helper"

RSpec.describe Identizer::DirectoryEntry do
  it "treats email as an alias for mail" do
    expect(described_class.from("a@b.com").mail).to eq("a@b.com")
    expect(described_class.new({ "email" => "a@b.com" }).mail).to eq("a@b.com")
  end

  it "backfills uid from the mail local-part and cn from the name" do
    entry = described_class.new({ "mail" => "alice@example.com", "givenName" => "Alice", "sn" => "Doe" })
    expect(entry.uid).to eq("alice")
    expect(entry["cn"]).to eq("Alice Doe")
  end

  it "falls back cn to uid when no name is given" do
    expect(described_class.new({ "mail" => "bob@example.com" })["cn"]).to eq("bob")
  end

  it "computes a DN from uid, ou and the base DN" do
    entry = described_class.new({ "mail" => "alice@example.com", "ou" => "staff" }, base_dn: "dc=corp")
    expect(entry.dn).to eq("uid=alice,ou=staff,dc=corp")
  end

  it "normalises memberOf into an array, dropping blanks" do
    entry = described_class.new({ "mail" => "a@b.com", "memberOf" => ["admins", "", "staff"] })
    expect(entry.groups).to eq(%w[admins staff])
  end

  describe "#to_identity" do
    subject(:claims) do
      described_class.new({
                            "mail" => "alice@example.com", "givenName" => "Alice", "sn" => "Doe",
                            "memberOf" => ["admins"], "department" => "eng"
                          }).to_identity.to_h
    end

    it "maps LDAP attributes to OIDC claims" do
      expect(claims).to include(
        "email" => "alice@example.com",
        "given_name" => "Alice",
        "family_name" => "Doe",
        "groups" => ["admins"],
        "preferred_username" => "alice"
      )
    end

    it "uses the DN as the subject and passes custom attributes through" do
      expect(claims).to include("sub" => "uid=alice,ou=people,dc=identizer,dc=local", "department" => "eng")
    end
  end
end
