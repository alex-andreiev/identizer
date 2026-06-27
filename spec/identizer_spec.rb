# frozen_string_literal: true

require "spec_helper"

RSpec.describe Identizer do
  after { described_class.reset_configuration! }

  it "yields the process-wide configuration to configure" do
    described_class.configure { |config| config.port = 4567 }
    expect(described_class.configuration.port).to eq(4567)
  end

  it "builds a Rack app that responds to call" do
    expect(described_class.app).to respond_to(:call)
  end

  it "resets the configuration" do
    described_class.configure { |config| config.port = 4567 }
    described_class.reset_configuration!
    expect(described_class.configuration.port).not_to eq(4567)
  end
end
