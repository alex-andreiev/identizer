# frozen_string_literal: true

require "spec_helper"

RSpec.describe Identizer::GrantStore do
  subject(:store) { described_class.new }

  it "stores and reads a value within its ttl" do
    store.put("k", "v", ttl: 60)
    expect(store.get("k")).to eq("v")
  end

  it "consumes a value with take (single-use)" do
    store.put("k", "v", ttl: 60)
    expect(store.take("k")).to eq("v")
    expect(store.take("k")).to be_nil
  end

  it "expires entries past their ttl" do
    store.put("k", "v", ttl: -1)
    expect(store.get("k")).to be_nil
    expect(store.size).to eq(0) # pruned on access
  end

  it "returns nil for missing keys" do
    expect(store.get("missing")).to be_nil
  end
end
