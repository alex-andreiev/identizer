# frozen_string_literal: true

require "spec_helper"
require "identizer/saml"
require "onelogin/ruby-saml"
require "rack/test"
require "rexml/document"
require "zlib"
require "tmpdir"

RSpec.describe "SAML IdP" do
  include Rack::Test::Methods

  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  end

  let(:acs) { "https://sp.example.com/acs" }
  let(:audience) { "https://sp.example.com/metadata" }
  let(:config) do
    Identizer::Configuration.new.tap do |c|
      c.config_dir = @dir
      c.url_host = "idp.test"
      c.seed_identities = [{ mail: "alice@example.com", givenName: "Alice", sn: "Doe" }]
    end
  end
  let(:app) { Identizer::App.new(config) }

  def saml_response_from(body)
    value = body[/name="SAMLResponse" value="([^"]*)"/, 1]
    CGI.unescapeHTML(value.to_s)
  end

  def settings
    OneLogin::RubySaml::Settings.new.tap do |s|
      s.assertion_consumer_service_url = acs
      s.sp_entity_id = audience
      s.idp_entity_id = config.issuer
      s.idp_cert = config.saml_keypair.certificate.to_pem
      s.issuer = audience
    end
  end

  def validate(base64_response)
    response = OneLogin::RubySaml::Response.new(base64_response, settings: settings)
    response.soft = true
    response
  end

  describe "metadata" do
    it "serves signed-IdP metadata advertising the SSO endpoint and signing cert" do
      get "/metadata"
      expect(last_response.status).to eq(200)
      expect(last_response.content_type).to start_with("application/xml")
      expect(last_response.body).to include("IDPSSODescriptor",
                                            config.saml_keypair.certificate_base64,
                                            "#{config.base_url}/saml/sso")
    end
  end

  describe "IdP-initiated SSO" do
    it "shows a login form bound to the ACS" do
      get "/saml/sso", acs: acs
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("SAML sign in", "alice@example.com", acs)
    end

    it "POSTs a valid signed Response carrying the attributes and RelayState" do
      post "/saml/finish", email: "alice@example.com", password: "password",
                           acs: acs, audience: audience, relay_state: "rs-42"

      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('name="RelayState" value="rs-42"')

      response = validate(saml_response_from(last_response.body))
      expect(response.is_valid?).to be(true)
      expect(response.nameid).to eq("alice@example.com")
      expect(response.attributes["given_name"]).to eq("Alice")
    end

    it "renders an error for a wrong password" do
      post "/saml/finish", email: "alice@example.com", password: "nope", acs: acs
      expect(last_response.body).to include("SAML error")
    end
  end

  describe "SP-initiated SSO" do
    def deflate(xml)
      stream = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
      out = stream.deflate(xml, Zlib::FINISH)
      stream.close
      out
    end

    def authn_request(id:)
      xml = <<~XML.delete("\n")
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{id}" Version="2.0"
          IssueInstant="2026-01-01T00:00:00Z" AssertionConsumerServiceURL="#{acs}">
          <saml:Issuer>#{audience}</saml:Issuer></samlp:AuthnRequest>
      XML
      Base64.strict_encode64(deflate(xml))
    end

    it "parses the AuthnRequest ACS and request ID into the login form" do
      get "/saml/sso", SAMLRequest: authn_request(id: "_req-9")
      expect(last_response.body).to include('value="_req-9"', "value=\"#{acs}\"")
    end

    it "echoes InResponseTo into a valid Response" do
      post "/saml/finish", email: "alice@example.com", password: "password",
                           acs: acs, audience: audience, in_response_to: "_req-9"

      base64 = saml_response_from(last_response.body)
      expect(validate(base64).is_valid?).to be(true)

      document = REXML::Document.new(Base64.decode64(base64))
      response_node = REXML::XPath.first(document, "/*[local-name()='Response']")
      expect(response_node.attributes["InResponseTo"]).to eq("_req-9")
    end
  end
end
