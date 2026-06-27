# frozen_string_literal: true

# Optional real SAML IdP support (signed assertions). Required on demand so the
# nokogiri dependency is only loaded when SAML signing is actually used.
require "nokogiri"
require "securerandom"

module Identizer
  # A minimal SAML 2.0 identity provider: signed Response/Assertion building.
  module Saml
  end
end

require_relative "saml/keypair"
require_relative "saml/signer"
require_relative "saml/encryptor"
require_relative "saml/response_builder"
